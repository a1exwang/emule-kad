require 'json'

module Kademlia
  module Utils
    class Prefs
      DEFAULT_PREFS_FILE_NAME = 'kad.json'
      attr_reader :kad_id, :kad_udp_port, :kad_tcp_port
      attr_reader :mtu

      def initialize(file_path = DEFAULT_PREFS_FILE_NAME)
        @file_path = file_path
        if File.exists?(@file_path)
          begin
            json = JSON.parse(File.read(@file_path))
            @kad = json['kad']
            @kad_id = @kad['id'] ? KadID.from_kad_bytes(@kad['id']) : init_my_kad_id
            @kad_udp_port = @kad['udp_port']
            @kad_tcp_port = @kad['tcp_port']
            @mtu = json['mtu']

            json['kad']['id'] = @kad_id
            File.write(file_path, JSON.pretty_generate(json))
          rescue JSON::JSONError
            raise "#{@file_path} format error"
          end
        end
      end

      def init_my_kad_id
        kad_id = Kademlia::KadID.from_kad_bytes(Array.new(16) { Random.rand(0...(1 << 8)) })
        LOG.logt('Prefs', "KadID generated: #{kad_id}")
        kad_id
      end

      def save
        File.write @file_path, to_json
      end

      def to_json
        kad = {
            id: @kad_id.kad_bytes
        }
        {
            kad: kad,
            mtu: @mtu
        }.to_json
      end
    end
  end

end
