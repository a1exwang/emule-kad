require_relative 'log'

module Kademlia
  class MessageQueue
    module Error
      UnknownMessageError = Class.new(Exception)
      UnHandledMessageError = Class.new(Exception)
      DuplicateHandlerError = Class.new(Exception)
    end

    # :initialized, :running, :stopped
    attr_reader :status

    DEFAULT_MAX_WORKER = 4
    def init_workers(n)
      @worker_queue = Queue.new
      @workers = Array.new(n) do |i|
        Thread.new do
          loop do
            job = @worker_queue.deq
            job.call
          end
        end
      end
    end

    ##
    # MessageQueue#add_worker_job(job)
    #   Add a job to worker queue.
    #   The +job+ is executed concurrently, so you can only call MessageQueue#<< or send_delay method.
    # @param job: Proc object (or any object that respond to 'call')
    def add_worker_job(&job)
      @worker_queue << job
    end

    ##
    # create a message queue and set handlers with block
    # @param block
    #
    # examples:
    #   MessageQueue.new do |handler|
    #     handler.on_req(lambda) do |m|
    #       # do something
    #     end
    #     handler.on(name) do |m|
    #       # do something
    #     end
    #     handler.on(name, lambda) do |m|
    #     end
    # message_handler = { name: 'a', filter: , handler:, ... }
    def initialize(worker_count = DEFAULT_MAX_WORKER, &block)
      @queue = Queue.new
      @handlers = {}
      @status = :initialized
      add_handlers(&block)
      init_workers(worker_count)
    end

    ##
    # similar to +MessageQueue.new+
    def add_handlers(&block)
      if @status == :running
        raise ArgumentError, 'cannot add handler to a running queue'
      end
      obj = MyObject.new
      block.call(obj)
      @handlers.merge!(obj.message_handlers) do |key, _val1, _val2|
        raise DuplicateHandlerError, "handler '#{key}' already defined"
      end
    end

    ##
    # add a message and execute without delay
    # @param: message, a hash object
    # note:
    #   these message names has special meanings and do not use them.
    #   '__quit'
    #   '__block'
    def <<(message)
      raise ArgumentError unless message.is_a?(Hash)
      @queue << message
    end

    def send_delay(seconds, message)
      raise ArgumentError unless seconds.is_a? Numeric
      Thread.new do
        sleep seconds
        self << message
      end
    end

    def send_block(&block)
      raise ArgumentError unless block
      self << {
          name: '__block',
          __block: block
      }
    end

    def clear
      @queue.clear
    end

    def clear_worker
      @worker_queue.clear
    end

    def quit
      if @status == :running
        self << { name: '__quit' }
      end
    end

    def start_blocking
      @status = :running
      loop do
        message = @queue.pop
        name = message[:name].to_s
        case name
          when '__block'
            message[:__block].call(message)
          when '__quit'
            LOG.logt('MessageQueue', 'Quiting...')
            break
          else
            if @handlers[name]
              handled = false
              @handlers[name].each do |handler|
                if !handler[:filter] || handler[:filter].call(message)
                  handler[:handler].call(message)
                  handled = true
                  break
                end
              end
              LOG.logt 'Message Queue', "message unhandled #{message}" unless handled
            else
              LOG.logt 'Message Queue', "unknown message #{message}"
            end
        end
      end
      @status = :stopped
    end

    private
    class MyObject
      attr_reader :message_handlers
      def initialize
        @message_handlers = Hash.new { Array.new }
      end
      def on(name, lambda = nil, &block)
        @message_handlers[name] += [{ filter: lambda, handler: block }]
      end
      # define on_xxx methods
      def method_missing(name, *params, &block)
        if name.to_s =~ /on_(.+)$/
          message_name = $1
          on(message_name, *params, &block)
        else
          super
        end
      end
    end
  end
end