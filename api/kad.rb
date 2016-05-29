require_relative '../log'
require_relative '../kad'
require 'sinatra'
require 'json'
require 'monitor'
require 'sinatra/config_file'
require 'sinatra/json'

# https://gist.github.com/pettyjamesm/3746457
class Semaphore

  def initialize(max_val = nil)
    max_val = max_val.to_i unless max_val.nil?
    raise ArgumentError.new('Semaphores must use a positive maximum value or have no maximum!') if max_val and max_val <= 0
    @max   = max_val || -1
    @count = 0
    @mon   = Monitor.new
    @d_wait = @mon.new_cond
    @u_wait = @mon.new_cond
  end

  def count
    @mon.synchronize { @count }
  end

  def up!(number = 1)
    if number > 1
      number.times { up!(1) }
      count
    else
      @mon.synchronize do
        @u_wait.wait while @max > 0 and @count == @max
        @d_wait.signal if @count == 0
        @count += 1
      end
    end
  end

  def down!(number = 1)
    if number > 1
      number.times { down!(1) }
      count
    else
      @mon.synchronize do
        @d_wait.wait while @count == 0
        @u_wait.signal if @count == @max
        @count -= 1
      end
    end
  end

  alias_method :wait, :down!
  alias_method :signal, :up!
end

class KadApi < Sinatra::Base
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

end
