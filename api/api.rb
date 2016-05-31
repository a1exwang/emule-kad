require_relative '../log'
require_relative '../kad'
require_relative '../bt-dht/bt-dht'
require 'sinatra'
require 'json'
require 'sinatra/config_file'
require 'sinatra/json'

class Api < Sinatra::Base
  register Sinatra::ConfigFile

  # use Rack::Auth::Basic, 'Restricted Area' do |username, password|
  #   username == 'alexwang' and password == '123'
  # end

  set show_exceptions: :after_handler
  config_file 'config/sinatra.yml'
  ApiError = Class.new Exception

  error JSON::JSONError do
    content_type :json
    { status: :failed, reason: 'json format error' }.to_json
  end
  error ApiError do
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
    json status: :not_found
  end

  get '/api/v1/kad/search_final_results_sync' do
    search_uid = params['search_uid']
    raise ApiError, 'parameter error' unless search_uid

    results = []
    # sem = ::Semaphore.new
    sem = Queue.new
    KadClient.instance.msg_get_final_search_results(search_uid) do |s|
      results = s.results
      # sem.signal
      sem.enq 0
    end
    sem.deq

    { status: :ok, results: results }.to_json
  end
  get '/api/v1/kad/search_results' do
    search_uid = params['search_uid']
    raise ApiError, 'parameter error' unless search_uid

    results = []
    # sem = ::Semaphore.new
    sem = Queue.new
    KadClient.instance.msg_get_search_results(search_uid) do |r|
      results = r
      sem.signal
      sem.enq 0
    end
    sem.deq

    { status: :ok, results: results }.to_json
  end
  post '/api/v1/kad/search' do
    keyword = params['keyword']
    raise ApiError, 'parameter error' unless keyword
    id = KadClient.instance.msg_search_keyword(keyword)
    { status: :ok, search_uid: id }.to_json
  end
  post '/api/v1/kad/search_sync' do
    keyword = params['keyword']
    raise ApiError, 'parameter error' unless keyword
    # sem = ::Semaphore.new
    sem = Queue.new
    results = []
    stream do |out|
      out << ' '
      KadClient.instance.msg_search_keyword(keyword) do |s|
        results = s.results_ed2k
        sem.enq 0
      end
      sem.deq
      out << { status: :ok, results: results.uniq }.to_json
    end
  end

  get '/api/v1/btdht/search_sync' do
    keyword = params['keyword']
    limit = params['limit']&.to_i || 100

    stream do |out|
      out << ' '
      sem = Queue.new
      results = []
      DHT::BTDigg.instance.search_limit_async(keyword, limit) do |r|
        results = r
        sem.enq 0
      end
      sem.deq
      out << { status: :ok, results: results.uniq }.to_json
    end
  end

end
