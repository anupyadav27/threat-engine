"""
Go Data Flow Analysis Module

Performs data flow analysis on Go programs to track variable values,
taint propagation, and security-relevant data flows.
"""

from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field

@dataclass
class DataFlowFact:
    """Data flow fact about a variable."""
    variable: str
    value_type: str  # 'literal', 'tainted', 'clean', 'unknown'
    source_location: Tuple[str, int]  # (file, line)
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TaintSource:
    """Source of tainted data."""
    name: str
    location: Tuple[str, int]
    source_type: str  # 'user_input', 'file_read', 'network', 'environment'
    confidence: float = 1.0

@dataclass 
class TaintSink:
    """Sink where tainted data should not flow."""
    name: str
    location: Tuple[str, int]
    sink_type: str  # 'command_exec', 'sql_query', 'file_write', 'log_output'
    risk_level: str  # 'high', 'medium', 'low'

@dataclass
class DataFlowViolation:
    """Data flow violation (e.g., tainted data reaching sink)."""
    source: TaintSource
    sink: TaintSink
    flow_path: List[Tuple[str, int]]  # List of (variable, line) in flow
    violation_type: str
    confidence: float

class DataFlowAnalyzer:
    """Go-specific data flow analyzer."""
    
    def __init__(self):
        self.taint_sources: List[TaintSource] = []
        self.taint_sinks: List[TaintSink] = []
        self.data_flow_facts: Dict[str, DataFlowFact] = {}
        self.violations: List[DataFlowViolation] = []
    
    def add_taint_source(self, source: TaintSource):
        """Add a taint source."""
        self.taint_sources.append(source)
    
    def add_taint_sink(self, sink: TaintSink):
        """Add a taint sink."""
        self.taint_sinks.append(sink)
    
    def analyze_data_flows(self, ast: Dict[str, Any], 
                          cfgs: Dict[str, Any], 
                          symbols: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data flows in the program."""
        
        # Initialize with Go-specific sources and sinks
        self._initialize_go_sources_and_sinks(ast)
        
        # Track variable assignments and flows
        self._track_variable_flows(ast)
        
        # Check for violations
        self._check_flow_violations()
        
        # Return analysis results
        return {
            'taint_sources': len(self.taint_sources),
            'taint_sinks': len(self.taint_sinks),
            'total_violations': len(self.violations),
            'violations_by_type': self._group_violations_by_type(),
            'high_risk_violations': len([v for v in self.violations if v.sink.risk_level == 'high']),
            'data_flow_facts': len(self.data_flow_facts),
            'violations': [self._format_violation(v) for v in self.violations[:10]]  # Limit output
        }
    
    def _initialize_go_sources_and_sinks(self, ast: Dict[str, Any]):
        """Initialize Go-specific taint sources and sinks."""
        filename = ast.get('filename', 'unknown')
        
        # Common Go taint sources
        go_taint_sources = [
            ('http.Request', 'user_input', 'high'),
            ('os.Args', 'command_line', 'medium'), 
            ('os.Getenv', 'environment', 'medium'),
            ('io.ReadAll', 'file_read', 'low'),
            ('bufio.Scanner', 'input_stream', 'medium')
        ]
        
        # Common Go taint sinks  
        go_taint_sinks = [
            ('exec.Command', 'command_exec', 'high'),
            ('sql.Query', 'sql_query', 'high'),
            ('sql.Exec', 'sql_query', 'high'),
            ('os.OpenFile', 'file_write', 'medium'),
            ('fmt.Printf', 'log_output', 'low'),
            ('log.Printf', 'log_output', 'low')
        ]
        
        # Add sources found in AST
        self._find_sources_in_ast(ast, go_taint_sources, filename)
        
        # Add sinks found in AST
        self._find_sinks_in_ast(ast, go_taint_sinks, filename)
    
    def _find_sources_in_ast(self, ast: Dict[str, Any], 
                            source_patterns: List[Tuple[str, str, str]],
                            filename: str):
        """Find taint sources in AST."""
        def search_nodes(nodes: List[Dict[str, Any]]):
            for node in nodes:
                if node.get('node_type') == 'call_expression':
                    func_name = node.get('properties', {}).get('function', '')
                    line = node.get('line', 0)
                    
                    for pattern, source_type, risk in source_patterns:
                        if pattern in func_name:
                            source = TaintSource(
                                name=func_name,
                                location=(filename, line),
                                source_type=source_type,
                                confidence=0.8 if risk == 'high' else 0.6
                            )
                            self.add_taint_source(source)
                
                # Recursively check children
                children = node.get('children', [])
                if children:
                    search_nodes(children)
        
        children = ast.get('children', [])
        search_nodes(children)
    
    def _find_sinks_in_ast(self, ast: Dict[str, Any],
                          sink_patterns: List[Tuple[str, str, str]], 
                          filename: str):
        """Find taint sinks in AST."""
        def search_nodes(nodes: List[Dict[str, Any]]):
            for node in nodes:
                if node.get('node_type') == 'call_expression':
                    func_name = node.get('properties', {}).get('function', '')
                    line = node.get('line', 0)
                    
                    for pattern, sink_type, risk in sink_patterns:
                        if pattern in func_name:
                            sink = TaintSink(
                                name=func_name,
                                location=(filename, line),
                                sink_type=sink_type,
                                risk_level=risk
                            )
                            self.add_taint_sink(sink)
                
                # Recursively check children
                children = node.get('children', [])
                if children:
                    search_nodes(children)
        
        children = ast.get('children', [])
        search_nodes(children)
    
    def _track_variable_flows(self, ast: Dict[str, Any]):
        """Track variable assignments and data flows."""
        filename = ast.get('filename', 'unknown')
        
        def track_in_nodes(nodes: List[Dict[str, Any]]):
            for node in nodes:
                if node.get('node_type') == 'assignment_expression':
                    self._process_assignment(node, filename)
                elif node.get('node_type') == 'call_expression':
                    self._process_call_assignment(node, filename)
                
                # Recursively process children
                children = node.get('children', [])
                if children:
                    track_in_nodes(children)
        
        children = ast.get('children', [])
        track_in_nodes(children)
    
    def _process_assignment(self, node: Dict[str, Any], filename: str):
        """Process variable assignment for data flow tracking."""
        properties = node.get('properties', {})
        variable = properties.get('variable', '')
        value = properties.get('value', '')
        line = node.get('line', 0)
        
        if not variable:
            return
        
        # Determine value type
        value_type = 'unknown'
        source_props = {}
        
        if properties.get('contains_literal', False):
            value_type = 'literal'
            source_props['literal_value'] = value
        elif any(source.name in value for source in self.taint_sources):
            value_type = 'tainted'
            source_props['taint_source'] = value
        else:
            value_type = 'clean'
        
        # Create data flow fact
        fact = DataFlowFact(
            variable=variable,
            value_type=value_type,
            source_location=(filename, line),
            properties=source_props
        )
        
        self.data_flow_facts[variable] = fact
    
    def _process_call_assignment(self, node: Dict[str, Any], filename: str):
        """Process function call that might assign tainted data."""
        properties = node.get('properties', {})
        func_name = properties.get('function', '')
        line = node.get('line', 0)
        
        # Check if this call returns tainted data
        is_taint_source = any(source.name == func_name for source in self.taint_sources)
        
        if is_taint_source:
            # This is a simplified approach - in reality we'd need to track
            # the actual variable being assigned to
            var_name = f"temp_var_{line}"
            
            fact = DataFlowFact(
                variable=var_name,
                value_type='tainted',
                source_location=(filename, line),
                properties={'source_function': func_name}
            )
            
            self.data_flow_facts[var_name] = fact
    
    def _check_flow_violations(self):
        """Check for data flow violations."""
        # Simple violation detection - check if tainted data could reach sinks
        for sink in self.taint_sinks:
            sink_file, sink_line = sink.location
            
            # Look for tainted facts that could reach this sink
            for var_name, fact in self.data_flow_facts.items():
                if fact.value_type == 'tainted':
                    fact_file, fact_line = fact.source_location
                    
                    # Simple heuristic: if tainted variable is defined before sink
                    # and in same file, it could flow to sink
                    if (fact_file == sink_file and 
                        fact_line < sink_line and 
                        sink_line - fact_line < 50):  # Within reasonable distance
                        
                        # Find corresponding source
                        source = self._find_source_for_fact(fact)
                        if source:
                            violation = DataFlowViolation(
                                source=source,
                                sink=sink,
                                flow_path=[(var_name, fact_line), ('sink', sink_line)],
                                violation_type=f"{source.source_type}_to_{sink.sink_type}",
                                confidence=min(source.confidence, 0.7)  # Reduce confidence for inference
                            )
                            self.violations.append(violation)
    
    def _find_source_for_fact(self, fact: DataFlowFact) -> Optional[TaintSource]:
        """Find the taint source corresponding to a data flow fact."""
        fact_file, fact_line = fact.source_location
        
        # Find closest source
        closest_source = None
        min_distance = float('inf')
        
        for source in self.taint_sources:
            source_file, source_line = source.location
            
            if source_file == fact_file:
                distance = abs(source_line - fact_line)
                if distance < min_distance:
                    min_distance = distance
                    closest_source = source
        
        return closest_source
    
    def _group_violations_by_type(self) -> Dict[str, int]:
        """Group violations by type."""
        counts = {}
        for violation in self.violations:
            violation_type = violation.violation_type
            counts[violation_type] = counts.get(violation_type, 0) + 1
        return counts
    
    def _format_violation(self, violation: DataFlowViolation) -> Dict[str, Any]:
        """Format violation for output."""
        return {
            'type': violation.violation_type,
            'source': {
                'name': violation.source.name,
                'location': f"{violation.source.location[0]}:{violation.source.location[1]}",
                'type': violation.source.source_type
            },
            'sink': {
                'name': violation.sink.name,
                'location': f"{violation.sink.location[0]}:{violation.sink.location[1]}",
                'type': violation.sink.sink_type,
                'risk': violation.sink.risk_level
            },
            'confidence': violation.confidence,
            'flow_path_length': len(violation.flow_path)
        }

def analyze_data_flow_for_ast(ast: Dict[str, Any], 
                             cfgs: Dict[str, Any],
                             symbols: Dict[str, Any]) -> Dict[str, Any]:
    """Main function to analyze data flow for Go AST."""
    analyzer = DataFlowAnalyzer()
    return analyzer.analyze_data_flows(ast, cfgs, symbols)