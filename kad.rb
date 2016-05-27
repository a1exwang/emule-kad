require_relative 'utils'
require_relative 'prefs'
require_relative 'packet'
require_relative 'kad_id'
require_relative 'message_queue'
require_relative 'bucket'
require_relative 'search'

require 'socket'

Thread.abort_on_exception = true

LOG = Kademlia::Utils::Logger.new

class KadClient
  def initialize(bootstrap_contacts)
    @prefs = Kademlia::Utils::Prefs.new
    @ip = KadClient.get_local_ip
    @root_bucket = Kademlia::Bucket.create_root(@prefs.kad_id)
    @bootstrap_contacts = bootstrap_contacts
    @searches = []
    init_udp
  end

  ##
  # add_contact(contact)
  # @param: contact, contact object or contact array
  def add_contact(contact)
    raise ArgumentError unless contact.is_a?(Kademlia::Contact)
    @root_bucket.add_contact(contact)
  end

  def init_udp
    @udp_socket = UDPSocket.new
    @udp_socket.bind(@ip, @prefs.kad_udp_port)
    @udp_thread = Thread.new do
      loop do
        data, addr = @udp_socket.recvfrom(@prefs.mtu)
        _, remote_port, _, _remote_ip = addr
        remote_ip = Kademlia::Utils::IPAddress.new(_remote_ip)

        begin
          packet = Kademlia::Packet.new(self, data, @ip, @prefs.kad_id, remote_ip, remote_port)
          if @message_queue
            @message_queue << {
                name: packet.opcode.to_s,
                content: packet
            }
          end
          LOG.logt 'UDP thread', "received from #{addr[2]}:#{addr[1]}, kad opcode '#{packet.opcode}'"
        rescue Kademlia::Error::InvalidKadPacket => e
          puts e
        end
      end
    end
  end

  def init_queue(q)
    @message_queue = q
  end

  def bootstrap
    find_node(@prefs.kad_id)
  end

  def search_keyword(keyword)
    # @contacts.each do |node|
    #   begin
    #     bytes = Kademlia::Packet::Helpers.kad2_search_key_req(node[:ip], node[:id], keyword, 4)
    #     @udp_socket.send(bytes.pack('C*'), 0, node[:ip].to_s, node[:udp_port])
    #     LOG.logt 'search_keyword', "keyword '#{keyword}' id #{} to #{node[:ip]}:#{node[:udp_port]}"
    #   rescue Errno::EINVAL => e
    #     puts e
    #   end
    # end
  end

  # get global ip address at local machine
  # return value: String. e.g. '1.1.1.1'
  def self.get_local_ip
    interface = `route | grep default`.split.last
    if `ifconfig #{interface}` =~ /inet addr:([.0-9]+)/i
      $1
    else
      raise RuntimeError, 'cannot get local ip'
    end
    # addrs = Socket.ip_address_list.reject { |x| ! x.ipv4? || x.ipv4_loopback? }
    # addrs.first.ip_address
  end

  ##
  # Wait for the kad client listeners
  def start
    @message_queue.start_blocking
  end

  def find_node(kad_id)
    contacts = @root_bucket.find_closest(kad_id, Kademlia::NodeIDSearch::FIND_NODE_COUNT)
    search = Kademlia::NodeIDSearch.new(kad_id, contacts)
    @searches << search
    @message_queue << {
        name: 'find_node',
        search: search
    }
  end

  def socket
    @udp_socket
  end

  def main1

    main = Kademlia::Contact.new(
        Kademlia::KadID.from_kad_bytes('a5 21 f3 2d 63 9f a8 56 56 c6 3e c1 09 55 0f d6'.split.map {|x| x.to_i(16)}) ,
        Kademlia::Utils::IPAddress.new(KadClient.get_local_ip),
        4672,
        4662,
        [0]*8,
        8
    )
    main2 = Kademlia::Contact.new(
        Kademlia::KadID.from_kad_bytes('02 ae ee 01 e0 2a c6 05 a1 0b ce c8 90 20 d0 67'.split.map {|x| x.to_i(16)}),
        Kademlia::Utils::IPAddress.new('192.168.199.5'),
        4672,
        4662,
        [0]*8,
        8
    )

    add_contact(main2)

    q = nil
    q = Kademlia::MessageQueue.new do |e|
      e.on('kad2_res') do |message|
        packet = message[:content]

        # 找到对应的search对象
        search = @searches.find { |search| search.id == packet.content[:target_id] }
        new_contacts = packet.content[:contacts]

        new_contacts.each do |c|
          add_contact(c)
          parent = @root_bucket.find do |x|
            x.ip == packet.content[:remote_ip] && x.udp_port == packet.content[:remote_udp_port]
          end
          if parent.nil?
            parent_id = @prefs.kad_id
            LOG.logt('kad2 res', 'add contact to search parent not found, maybe delete by insertion')
          else
            parent_id = parent.id
            search.add_contact_by_parent_id(c, parent_id)
          end
        end
      end
      e.on('bootstrap_timer') do
        bootstrap
      end
      e.on('small_timer') do
        search_keyword('abc')
      end
      e.on('udp_send') do |message|
        ip, port, str = message[:ip], message[:port], message[:str]
        begin
          @udp_socket.send(str, 0, ip, port)
        rescue Errno::EINVAL => ex
          puts ex
        end
        LOG.logt('upd_send', "send #{str.bytes.size} bytes")
      end

      e.on('find_node') do |message|
        search = message[:search]
        kad_id = search.id
        result = search.get_unsent_contacts_and_set_sent
        if result.size == 0
          # start sending find key request
          LOG.logt('find_node', 'find node stall!!!!!!!!!')
          search.log_self
        else
          # send find node request to nearer contacts
          result.each do |c|
            contact = c[:contact]
            bytes = Kademlia::Packet::Helpers.kad2_req(0xb, contact.ip, contact.id, kad_id, contact.version)
            q << {
                name: 'udp_send',
                str: bytes.pack('C*'),
                ip: contact.ip.to_s,
                port: contact.udp_port
            }
            LOG.logt 'find_node', "target '#{kad_id}' to #{contact.ip}:#{contact.udp_port}"
          end

          q.send_delay(5, name: 'find_node', search: search)
        end
      end
    end

    init_queue(q)
    q.send_delay(0.5, name: 'bootstrap_timer')
    start
  end
end

bootstrap_contacts = Kademlia::Utils::Helpers.parse_nodes_dat('nodes.dat')
kad_client = KadClient.new(bootstrap_contacts)
kad_client.main1