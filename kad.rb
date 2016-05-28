require_relative 'utils'
require_relative 'prefs'
require_relative 'packet'
require_relative 'kad_id'
require_relative 'message_queue'
require_relative 'bucket'
require_relative 'search'

require 'socket'

Thread.abort_on_exception = true
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

  def merge_bootstrap_contacts
    @bootstrap_contacts.each do |c|
      @root_bucket.add_contact c
    end
  end

  def init_udp
    @udp_socket = UDPSocket.new
    @udp_socket.bind(@ip, @prefs.kad_udp_port)
    @udp_thread = Thread.new do
      loop do
        data, addr = @udp_socket.recvfrom(@prefs.mtu)
        _, remote_port, _, _remote_ip = addr
        remote_ip = Kademlia::Utils::IPAddress.new(_remote_ip)
        @message_queue << {
            name: 'receive_udp_packet',
            ip: remote_ip,
            port: remote_port,
            data: data
        }
      end
    end
  end

  def init_queue(q)
    @message_queue = q
  end

  def bootstrap
    find_node(@prefs.kad_id)
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
  def search_keyword(keyword)
    target_id = Kademlia::KadID.from_utf8_str(keyword)
    init_contacts = @root_bucket.find_closest(target_id, Kademlia::NodeIDSearch::FIND_NODE_COUNT)
    search = Kademlia::KeywordSearch.new(keyword, init_contacts)
    @searches << search
    @message_queue << {
        name: 'find_node',
        search: search
    }
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


  def socket
    @udp_socket
  end

  def socket_send(ip, port, str)
    @message_queue << {
        name: 'udp_send',
        str: str,
        ip: ip.to_s,
        port: port
    }
  end

  def send_find_key_request(contact, keyword)
    bytes = Kademlia::Packet::Helpers.kad2_search_key_req(contact.ip, contact.id, keyword, contact.version)
    socket_send(contact.ip, contact.udp_port, bytes.pack('C*'))
  end

  def main1

    main = Kademlia::Contact.new(
        Kademlia::KadID.from_kad_bytes('a5 21 f3 2d 63 9f a8 56 56 c6 3e c1 09 55 0f d6'.split.map {|x| x.to_i(16)}) ,
        Kademlia::Utils::IPAddress.new('183.173.56.64'),
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
    # merge_bootstrap_contacts

    q = nil
    q = Kademlia::MessageQueue.new do |e|
      e.on('receive_udp_packet') do |message|
        remote_ip = message[:ip]
        remote_port = message[:port]
        c = @root_bucket.find_contact_by_ip_port(remote_ip, remote_port)
        data = message[:data]
        packet = Kademlia::Packet.new(self, data, @ip, @prefs.kad_id, c)
        if @message_queue
          @message_queue << {
              name: packet.opcode.to_s,
              content: packet
          }
        end
        LOG.logt 'UDP thread', "received from #{remote_ip}:#{remote_port}, kad opcode '#{packet.opcode}'"
      end
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
            # LOG.logt('kad2 res', 'add contact to search parent not found, maybe delete by insertion')
            search.add_contact_by_parent_id(c, nil)
          else
            parent_id = parent.id
            search.add_contact_by_parent_id(c, parent_id)
          end
        end
      end

      e.on('kad2_search_res') do |message|
        packet = message[:content]
        LOG.logt('kad2_find_res', "packet: #{packet}")
        search = @searches.find do |x|
          x.is_a?(Kademlia::KeywordSearch) && x.id == packet.content[:target_id]
        end
        if search
          search.add_search_res(packet.content)
        end
        # File.write(Time.now.strftime('dump/res-%H-%M-%S.%6N.json'), JSON.pretty_generate(packet.content))
        # parse kad2 find res and add to result list
      end

      e.on('bootstrap_timer') do
        bootstrap
      end
      e.on('small_timer') do
        search_keyword('abc')
      end
      e.on('save_search_results') do
        @searches.each do |s|
          if s.is_a?(Kademlia::KeywordSearch) && !s.saved && Time.now - s.last_search_res_at > 10 # 10 seconds of silence means the search has stalled
            File.write('results/' + s.search_name + '.json', JSON.pretty_generate(s))
            s.saved = true
            LOG.logt('save_search_results', "search '#{s.search_name}' done, save to .json")
          end
        end
      end
      e.on('udp_send') do |message|
        ip, port, str = message[:ip], message[:port], message[:str]
        begin
          @udp_socket.send(str, 0, ip, port)
        rescue Errno::EINVAL => ex
          puts ex
        end
        # LOG.logt('upd_send', "send #{str.bytes.size} bytes")
      end

      e.on('find_node') do |message|
        search = message[:search]
        kad_id = search.id
        result = search.get_unsent_contacts_and_set_sent
        if result.size == 0
          # start sending find key request
          LOG.logt('find_node', 'find node stall!!!!!!!!!')
          search.log_self
          if search.is_a?(Kademlia::KeywordSearch)
            # send find key request
            search.get_closest_contacts.each do |c|
              send_find_key_request(c[:contact], search.keyword)
            end
          end
        else
          # send find node request to nearer contacts
          result.each do |c|
            contact = c[:contact]
            bytes = Kademlia::Packet::Helpers.kad2_req(0xb, contact.ip, contact.id, kad_id, contact.version)
            socket_send(contact.ip, contact.udp_port, bytes.pack('C*'))
            LOG.logt 'find_node', "target '#{kad_id}' to #{contact.ip}:#{contact.udp_port}"
          end

          q.send_delay(2, name: 'find_node', search: search)
        end
      end
    end

    init_queue(q)
    q.send_delay(0.5, name: 'bootstrap_timer')
    Thread.new { sleep 8; self.search_keyword('abc') }
    Thread.new do
      loop do
        sleep 5
        q << { name: 'save_search_results' }
      end
    end
    # Thread.new { send_find_key_request(main, 'abc') }
    self.start
  end
end

bootstrap_contacts = Kademlia::Utils::Helpers.parse_nodes_dat('nodes.dat')
kad_client = KadClient.new(bootstrap_contacts)
kad_client.main1