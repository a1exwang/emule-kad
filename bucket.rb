require_relative 'utils'
require_relative 'kad_id'
require_relative 'contact'

module Kademlia

  class Bucket

    MAX_DEPTH = KadID::BIT_WIDTH
    BUCKET_SIZE = 3000
    attr_reader :left, :right, :parent
    attr_reader :depth
    attr_reader :contacts
    attr_reader :this_bit

    def self.create_root(self_kad_id)
      Bucket.new(0, nil, self_kad_id, 0)
    end

    def initialize(depth, parent, self_kad_id, this_bit)
      @depth = depth
      @parent = parent
      @contacts = []
      @self_kad_id = self_kad_id
      @left = nil
      @right = nil
      @this_bit = this_bit
    end

    def main_chain?
      @self_kad_id.bit(@depth) == @this_bit
    end

    ##
    # Bucket#add_node(kad_node)
    # @param contact: Kademlia::Contact
    def add_contact(contact)
      # leaf node
      if self.leaf?
        # return if @contacts.include?(contact)
        insert_contact(contact)

        # leaf node that may become a branch node after insertion
        if @contacts.size >= BUCKET_SIZE
          if @depth < MAX_DEPTH && main_chain?
            # split into to two buckets
            l, r = self.contact_partition
            @left = Bucket.new(depth + 1, self, @self_kad_id, @self_kad_id.bit(MAX_DEPTH - 1 - @depth))
            @right = Bucket.new(depth + 1, self, @self_kad_id, 1 - @self_kad_id.bit(MAX_DEPTH - 1 - @depth))
            l.each { |c| @left.add_contact(c) }
            r.each { |c| @right.add_contact(c) }
            @contacts = []
          else
            # remove old contacts
            @contacts = (@contacts.sort { |x, y| x.last_respond_at <=> y.last_respond_at }).last(BUCKET_SIZE)
          end
        end
      else
        # branch node
        contact.id.bit(MAX_DEPTH - 1 - depth) == @self_kad_id.bit(MAX_DEPTH - 1 - depth) ?
            @left.add_contact(contact) : @right.add_contact(contact)
      end
    end

    ##
    # Bucket#find_closest(kad_id, n)
    # @param kad_id the target kad id to find
    # @param n get +n+ closest targets
    def find_closest(kad_id, n)
      if self.leaf?
        (@contacts.sort { |x, y| (x.id ^ kad_id) <=> (y.id ^ kad_id) }).take [@contacts.size, n].min
      else
        children = [@left, @right]
        if kad_id.bit(MAX_DEPTH - 1 - @depth) != @self_kad_id.bit(MAX_DEPTH - 1 - @depth)
          children.reverse!
          puts 'go right'
        else
          puts 'go left'
        end

        targets = children.first.find_closest(kad_id, n)
        if targets.size < n
          targets += children.last.find_closest(kad_id, n)
        end
        targets
      end
    end

    ##
    # Bucket#update

    ##
    # search a contact from ip and port
    # @param ip: IPAddress
    # @param port: uint16
    def find_contact_by_ip_port(ip, port)
      if self.leaf?
        @contacts.each do |c|
          if c.ip == ip && c.udp_port == port
            return c
          end
        end
      else
        @left.each(&block)
        @right.each(&block)
      end
      nil
    end

    ##
    # Bucket#contact_count
    def contact_count
      if self.leaf?
        @contacts.size
      else
        @left.contact_count + @right.contact_count
      end
    end

    include Enumerable
    def each(&block)
      if self.leaf?
        @contacts.each(&block)
      else
        @left.each(&block)
        @right.each(&block)
      end
    end

    ##
    # Bucket#leaf?
    def leaf?
      @left == nil && @right == nil
    end

    def print_dbg
      tmp = self
      bits = []
      while tmp
        bits << tmp.this_bit
        tmp = tmp.parent
      end
      if leaf?
        puts "depth #{@depth}, #{bits.reverse.join('')}, contact count #{@contacts.size}"
      end
      # puts '  ' * @depth + "depth #{@depth}, #{bits.reverse.join('')}, contact count #{@contacts.size}"
      if @left
        @left.print_dbg
      end
      if @right
        @right.print_dbg
      end
    end

    def insert_contact(c)
      @contacts << c
    end

    def contact_partition
      @contacts.partition do |c|
        c.id.bit(MAX_DEPTH - 1 - @depth) == @self_kad_id.bit(MAX_DEPTH - 1 - @depth)
      end
    end

  end
end
#
# def random_kad_id
#   Kademlia::KadID.new(Array.new(16) { Random.rand(0...(1<<8)) })
# end
# root = Kademlia::Bucket.new(0, nil, Kademlia::KadID.new([0]*16), 0)
#
# 100000.times do |i|
#   id = random_kad_id
#   contact = Kademlia::Contact.new(id, nil, nil, nil, nil, nil)
#   root.add_contact(contact)
# end
#
# root.print_dbg
# target = random_kad_id
# puts "target: #{target.to_s_uint128}"
# y = root.find_closest(target, 10)
# y.each do |x|
#   puts "result, dis: #{(x.id^target).highest_one}, id: #{x.id.to_s_uint128}"
# end
# puts "total #{root.contact_count}"