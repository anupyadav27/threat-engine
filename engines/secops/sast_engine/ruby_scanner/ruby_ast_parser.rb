#!/usr/bin/env ruby
# Ruby AST Parser Script - emulates whitequark parser approach used by SonarSource
# This script uses Ruby's parser gem to generate AST information for the Python scanner

require 'json'

begin
  require 'parser/current'
rescue LoadError
  puts STDERR, "Error: parser gem not found. Install with: gem install parser"
  exit 1
end

def extract_node_info(node, source_lines = nil)
  return nil if node.nil?
  
  info = {
    'type' => node.type.to_s,
    'children' => []
  }
  
  # Add location information if available
  if node.respond_to?(:loc) && node.loc
    info['location'] = {
      'line' => node.loc.line,
      'column' => node.loc.column,
      'begin_pos' => node.loc.begin_pos,
      'end_pos' => node.loc.end_pos
    }
  end
  
  # Extract name/identifier information based on node type
  case node.type
  when :def, :defs
    # Method definition - extract method name
    info['name'] = node.children[0].to_s if node.children[0]
    info['params'] = extract_method_params(node) if node.children.length > 1
  when :class
    # Class definition - extract class name
    if node.children[0] && node.children[0].type == :const
      info['name'] = node.children[0].children[1].to_s
    end
    # Extract superclass if present
    if node.children[1]
      info['superclass'] = extract_const_name(node.children[1])
    end
  when :module
    # Module definition - extract module name
    if node.children[0] && node.children[0].type == :const
      info['name'] = node.children[0].children[1].to_s
    end
  when :send
    # Method call - extract receiver and method name
    receiver = node.children[0]
    method_name = node.children[1]
    args = node.children[2..-1]
    
    info['receiver'] = extract_node_info(receiver, source_lines) if receiver
    info['method_name'] = method_name.to_s if method_name
    info['args'] = args.map { |arg| extract_node_info(arg, source_lines) } if args.any?
  when :lvasgn, :ivasgn, :cvasgn, :gvasgn, :casgn
    # Variable assignment - extract variable name and value
    info['var_name'] = node.children[0].to_s
    info['var_type'] = case node.type
                      when :lvasgn then 'local'
                      when :ivasgn then 'instance'
                      when :cvasgn then 'class'
                      when :gvasgn then 'global'
                      when :casgn then 'constant'
                      end
    info['value'] = extract_node_info(node.children[1], source_lines) if node.children[1]
  when :lvar, :ivar, :cvar, :gvar
    # Variable reference
    info['var_name'] = node.children[0].to_s
    info['var_type'] = case node.type
                      when :lvar then 'local'
                      when :ivar then 'instance'
                      when :cvar then 'class'
                      when :gvar then 'global'
                      end
  when :const
    # Constant reference
    info['name'] = extract_const_name(node)
  when :if, :unless, :case
    # Conditional statements
    info['condition_type'] = node.type.to_s
    info['condition'] = extract_node_info(node.children[0], source_lines) if node.children[0]
  when :while, :until, :for
    # Loop statements
    info['loop_type'] = node.type.to_s
    info['condition'] = extract_node_info(node.children[0], source_lines) if node.children[0]
  when :rescue
    # Rescue clauses
    info['exception_types'] = extract_rescue_types(node)
  when :str, :int, :float, :sym, :true, :false, :nil
    # Literal values
    info['literal_type'] = node.type.to_s
    info['value'] = node.children[0]
  when :return
    # Return statements
    info['value'] = extract_node_info(node.children[0], source_lines) if node.children[0]
  end
  
  # Process child nodes
  node.children.each do |child|
    if child.is_a?(Parser::AST::Node)
      child_info = extract_node_info(child, source_lines)
      info['children'] << child_info if child_info
    end
  end
  
  info
end

def extract_method_params(def_node)
  return [] unless def_node.children[1]
  
  args_node = def_node.children[1]
  params = []
  
  args_node.children.each do |arg|
    case arg.type
    when :arg
      params << { 'name' => arg.children[0].to_s, 'type' => 'required' }
    when :optarg
      params << { 'name' => arg.children[0].to_s, 'type' => 'optional' }
    when :restarg
      params << { 'name' => arg.children[0].to_s, 'type' => 'splat' }
    when :kwarg
      params << { 'name' => arg.children[0].to_s, 'type' => 'keyword' }
    when :kwoptarg
      params << { 'name' => arg.children[0].to_s, 'type' => 'keyword_optional' }
    when :kwrestarg
      params << { 'name' => arg.children[0].to_s, 'type' => 'keyword_splat' }
    when :blockarg
      params << { 'name' => arg.children[0].to_s, 'type' => 'block' }
    end
  end
  
  params
end

def extract_const_name(const_node)
  return '' unless const_node
  
  case const_node.type
  when :const
    if const_node.children[0]
      "#{extract_const_name(const_node.children[0])}::#{const_node.children[1]}"
    else
      const_node.children[1].to_s
    end
  when :cbase
    ''
  else
    const_node.to_s
  end
end

def extract_rescue_types(rescue_node)
  types = []
  rescue_node.children.each do |child|
    if child.is_a?(Parser::AST::Node)
      case child.type
      when :const
        types << extract_const_name(child)
      when :array
        child.children.each do |array_child|
          if array_child.type == :const
            types << extract_const_name(array_child)
          end
        end
      end
    end
  end
  types
end

def analyze_security_patterns(ast_info)
  security_issues = []
  
  def traverse_for_security(node, issues)
    return unless node.is_a?(Hash)
    
    # Check for dangerous method calls
    if node['type'] == 'send' && node['method_name']
      dangerous_methods = ['eval', 'instance_eval', 'class_eval', 'module_eval', 'system', 'exec', 'spawn']
      if dangerous_methods.include?(node['method_name'])
        issues << {
          'type' => 'dangerous_method_call',
          'method' => node['method_name'],
          'location' => node['location']
        }
      end
    end
    
    # Check for hardcoded credentials in string literals
    if node['type'] == 'str' && node['value'].is_a?(String)
      value = node['value'].downcase
      if value.include?('password') || value.include?('secret') || value.include?('key') || value.include?('token')
        if value.length > 8  # Avoid flagging short descriptive strings
          issues << {
            'type' => 'potential_hardcoded_credential',
            'value' => node['value'],
            'location' => node['location']
          }
        end
      end
    end
    
    # Check for bare rescue clauses
    if node['type'] == 'rescue' && node['exception_types'].empty?
      issues << {
        'type' => 'bare_rescue_clause',
        'location' => node['location']
      }
    end
    
    # Recursively check children
    if node['children']
      node['children'].each { |child| traverse_for_security(child, issues) }
    end
  end
  
  traverse_for_security(ast_info, security_issues)
  security_issues
end

# Main execution
if ARGV.length < 1
  puts "Usage: #{$0} <ruby_file>"
  exit 1
end

file_path = ARGV[0]

begin
  source = File.read(file_path)
  source_lines = source.lines
  
  # Parse with Ruby parser
  ast = Parser::CurrentRuby.parse(source)
  
  if ast
    # Extract comprehensive AST information
    ast_info = extract_node_info(ast, source_lines)
    
    # Add security analysis
    security_issues = analyze_security_patterns(ast_info)
    
    # Output structured data for Python scanner
    result = {
      'success' => true,
      'file' => file_path,
      'ast' => ast_info,
      'security_issues' => security_issues,
      'parser_version' => Parser::VERSION
    }
    
    puts JSON.pretty_generate(result)
  else
    puts JSON.pretty_generate({
      'success' => false,
      'error' => 'Failed to parse Ruby code',
      'file' => file_path
    })
  end
  
rescue Parser::SyntaxError => e
  puts JSON.pretty_generate({
    'success' => false,
    'error' => 'Syntax error in Ruby code',
    'message' => e.message,
    'file' => file_path
  })
rescue => e
  puts JSON.pretty_generate({
    'success' => false,
    'error' => 'Unexpected error',
    'message' => e.message,
    'file' => file_path
  })
end