require_relative '../log'
require 'sinatra'
require 'json'

class KadApi < Sinatra::Base
  use Rack::Auth::Basic, 'Restricted Area' do |username, password|
    username == 'alexwang' and password == '123'
  end

  set show_exceptions: :after_handler

  MyError = Class.new Exception
  error JSON::JSONError do
    content_type :json
    { status: :failed, reason: 'json format error' }.to_json
  end
  error MyError do
    content_type :json
    e = env['sinatra.error']
    { status: :failed, reason: e.to_s }.to_json
  end
  error Exception do
    content_type :json
    e = env['sinatra.error']
    { status: :failed, reason: 'format error', e: e }.to_json
  end
  not_found do
    status 404
    { status: :not_found }.to_json
  end

  get '/api/v1/kad/search_status' do
    { status: :ok }.to_json
  end

  get '/api/v1/kad/search_results' do
    { status: :ok }.to_json
  end

  post '/api/v1/kad/search' do
    { status: :ok }.to_json
  end
end
