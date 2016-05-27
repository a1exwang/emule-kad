module Kademlia
  class MessageQueue
    module Error
      UnknownMessageError = Class.new(Exception)
      UnHandledMessageError = Class.new(Exception)
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
    def initialize(&block)
      @queue = Queue.new
      obj = MyObject.new
      block.call(obj)
      @handlers = obj.message_handlers
    end

    def <<(message)
      @queue << message
    end

    def send_delay(seconds, message)
      raise ArgumentError unless seconds.is_a? Numeric
      Thread.new do
        sleep seconds
        self << message
      end
    end

    def start_blocking
      loop do
        message = @queue.pop
        name = message[:name]
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
          raise Error::UnknownMessageError, "message name: #{name}"
        end
      end
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