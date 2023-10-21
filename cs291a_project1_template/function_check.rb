# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

HEADERS = "headers"
AUTH = "authorization"
PATH = "path"
CONTTYPE = "content-type"

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  headers = event[HEADERS].keys
  for header in headers
    if header.casecmp?(CONTTYPE)
      event[HEADERS][CONTTYPE] = event[HEADERS][header]
    end
    
    if header.casecmp?(AUTH)
      event[HEADERS][AUTH] = event[HEADERS][header]
    end
  end
  
  case event["httpMethod"]
  when "GET"
    begin
      if event[PATH] == "/token"
        return response(body: nil, status: 405)
      end
      
      if event[PATH] != "/"
        return response(body: nil, status:404)
      end
      
      if event[HEADERS][AUTH].split(" ")[0] != "Bearer"
        return response(body: nil, status: 403)
      end
      
      token = event[HEADERS][AUTH].split(" ")[1]
      payload = JWT.decode(token, "ITSASECRET")
      
    rescue JWT::ImmatureSignature, JWT::ExpiredSignature => e
      return response(body: nil, status: 401)
      
    rescue JWT::DecodeError => e
      return response(body: nil, status: 403)
      
    rescue
      return response(body: nil, status: 403)
      
    else
      return response(body: payload[0]["data"], status: 200)
    end
    
  when "POST"
    if event[PATH] == "/"
      return response(body: nil, status: 405)
    end
    
    if event[HEADERS][CONTTYPE] != "application/json"
      return response(body: nil, status: 415)
    end
    
    begin
      JSON.parse(event["body"])
    rescue
      return response(body: event, status: 422)
    else
      payload = {
        data: JSON.parse(event["body"]),
        exp: Time.now.to_i + 5,
        nbf: Time.now.to_i + 2
      }
      
      token = JWT.encode payload, "ITSASECRET", 'HS256'
      return response(body: {"token" => token}, status: 201)
    end
  
  else
    return response(body: nil, status: 405)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
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