require 'openssl'
require 'json'

module Kademlia
  class KadID
    BIT_WIDTH = 128
    BYTE_WIDTH = 16
    attr_reader :le_bytes

    # the we have >, <, >=, <=, ==...
    include Comparable
    def <=>(other)
      BYTE_WIDTH.times do |i|
        v = @le_bytes[BYTE_WIDTH - 1 - i] <=> other.le_bytes[BYTE_WIDTH - 1 - i]
        return v if v != 0
      end
      0
    end

    ##
    # from le array
    def initialize(arr)
      if arr.is_a?(Array) && arr.size == 16
        arr.each do |x|
          raise ArgumentError, 'invalid uint8 array' unless x >= 0 && x < 256
        end
        @le_bytes = arr.dup
      else
        raise ArgumentError, 'parameter must be an uint8 array'
      end
    end

    def be_bytes
      @le_bytes.reverse
    end

    def bit(n)
      raise ArgumentError unless 0 <= n && n < BIT_WIDTH
      byte_n = n / 8
      off = n % 8
      (@le_bytes[byte_n] >> off) & 1
    end

    def highest_one
      (0...BYTE_WIDTH).reverse_each do |i|
        (0...8).reverse_each do |j|
          return i*8 + j if @le_bytes[i] & (1 << j) != 0
        end
      end
      -1
    end

    def to_json(state = nil)
      kad_bytes.to_json
    end

    def kad_bytes
      @le_bytes.pack('C*').unpack('V4').reverse.pack('V4').bytes
    end

    def self.from_kad_bytes(arr)
      KadID.new arr.pack('C*').unpack('V4').reverse.pack('V4').bytes
    end

    def self.from_utf8_str(str)
      KadID.new OpenSSL::Digest::MD4.digest(str.force_encoding('utf-8')).bytes.reverse
    end

    def equal?(other)
      (self <=> other) == 0
    end

    def ^(other)
      new_arr = []
      @le_bytes.each_with_index do |b, i|
        new_arr[i] = @le_bytes[i] ^ other.le_bytes[i]
      end
      KadID.new(new_arr)
    end

    def dis(other)
      self ^ other
    end

    def to_s
      kad_bytes.map { |x| '%02x' % x }.join(' ')
    end

    def to_s_uint128
      be_bytes.map { |x| '%02x' % x }.join(' ')
    end

    def to_s_ed2k
      be_bytes.map { |x| '%02x' % x }.join('').upcase
    end

  end

end