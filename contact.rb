require 'time'

module Kademlia
  class Contact
    attr_reader :id, :ip, :udp_port, :tcp_port, :udp_key, :version
    attr_reader :last_respond_at

    def initialize(id, ip, udp_port, tcp_port, udp_key, version)
      @id = id
      @ip = ip
      @udp_port = udp_port
      @tcp_port = tcp_port
      @udp_key = udp_key
      @version = version
      @created_at = Time.now
      @last_respond_at = @created_at
    end

    include Comparable
    def <=>(other)
      @id <=> other.id
    end

    def update_responding_time
      @last_respond_at = Time.now
    end

  end
end