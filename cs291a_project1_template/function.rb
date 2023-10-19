# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  # Create cases on different possibilities for path.
  case event['path']
  when '/'
    if event['httpMethod'] == 'GET'
      # Handle GET request to '/'.
      handle_get_request(event)
    else
      # In this case, the client is trying to misuse a verb, respond 405.
      response(body: { error: 'Method Not Allowed' }, status: 405)
    end
  when '/token'
    if event['httpMethod'] == 'POST'
      # Handle POST request to '/token'.
      handle_post_token_request(event)
    else
      # In this case, the client is trying to misuse a verb, respond 405.
      response(body: { error: 'Method Not Allowed' }, status: 405)
    end
  else
    response(body: { error: 'Page Not Found' }, status: 404)
  end
end

# Response method for empty body, 200
def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

# Method to handle GET request.
def handle_get_request(event)
  auth_header = event['headers']['Authorization']
  # Check authorization header matches Bearer
  if auth_header && auth_header.match(/^Bearer (.*)/)
    # Question -- what is the point of having token = $1?
    token = $1
    begin
      decoded_token = JWT.decode token, ENV['JWT_SECRET'], true, { algorithm: 'HS256' }
      # Appropriate calls will return 200 OK.
      response(body: { data: decoded_token[0]['data'] }, status: 200)
    rescue JWT::ExpiredSignature
      # An expired token will throw 401 Unauthorized. 
      response(body: { error: 'Unauthorized' }, status: 401)
    rescue JWT::ImmatureSignature
      # An not-yet-valid token will throw 401 Unauthorized. 
      response(body: { error: 'Unauthorized' }, status: 401)
    rescue JWT::DecodeError
      # Authorization: Bearer <TOKEN> header missing, respond 403.
      response(body: { error: 'Forbidden' }, status: 403)
    end
  else
    # Catch all unwanted behavior with 403 Forbidden.
    response(body: { error: 'Forbidden' }, status: 403)
  end
end

# Method to handle POST request.
def handle_post_token_request(event)
  content_type = event['headers']['Content-Type']

  # If there is aContent-Type header andit is not 'application/json', respond 415.
  if !content_type.nil? && content_type != 'application/json'
    return response(body: { error: 'Unsupported Media Type' }, status: 415)
  end

  # Define event body (to avoid redundancy in code).
  body = event["body"]

  # If body is nil or empty, respond 422.
  if body.nil? || body.strip.empty?
    return response(body: { error: 'Unprocessable Entity' }, status: 422)
  end

  begin
    # Parse JSON from body. 
    data = JSON.parse(event["body"])
  rescue JSON::ParserError
    # If JSON is invalid, respond 422.
    return response(body: { error: 'Unprocessable Entity' }, status: 422)
  end

  # Define payload.
  payload = {
    data: JSON.parse(event["body"]),
    exp: Time.now.to_i + 5,
    nbf: Time.now.to_i + 2
  }
  token = JWT.encode(payload, ENV['JWT_SECRET'], 'HS256')
  # On success, returns a json document of the format {"token": <GENERATED_JWT>} with status code 201.
  response(body: { "token"=>token }, status: 201)
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
