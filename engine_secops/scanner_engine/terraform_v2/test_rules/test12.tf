# Test case for creating public API (rule trigger)

resource "aws_api_gateway_rest_api" "test_api" {
  name        = "public-api"
  description = "A test API that is public (no authorization)"
}

resource "aws_api_gateway_resource" "test_resource" {
  rest_api_id = aws_api_gateway_rest_api.test_api.id
  parent_id   = aws_api_gateway_rest_api.test_api.root_resource_id
  path_part   = "public"
}

resource "aws_api_gateway_method" "public_method" {
  rest_api_id   = aws_api_gateway_rest_api.test_api.id
  resource_id   = aws_api_gateway_resource.test_resource.id
  http_method   = "GET"
  authorization = "NONE"   # 🚨 This will trigger the rule
}

resource "aws_api_gateway_integration" "test_integration" {
  rest_api_id             = aws_api_gateway_rest_api.test_api.id
  resource_id             = aws_api_gateway_resource.test_resource.id
  http_method             = aws_api_gateway_method.public_method.http_method
  type                    = "MOCK"
  integration_http_method = "POST"
}
