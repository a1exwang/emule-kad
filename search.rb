require_relative 'kad_id'

module Kademlia

  class Search
    attr_reader :id
    def initialize(id)
      @id = id
    end
  end

  ##
  # NodeIDSearch
  # @contact_generations数组保存了最多KadID::BIT_WIDTH代数的contact数组
  # 代(generation)的定义为:
  #   1.自己为第-1代中的唯一元素;
  #   2. 对第i代中的contact发送查询请求, 得到的结果集合为第i+1代
  class NodeIDSearch < Search
    def initialize(id, init_contacts)
      super(id)
      @contact_generations = []
      init_contacts.each do |c|
        add_contact(c)
      end
    end

    ##
    #
    def add_contact(contact, parent = nil)
      if parent
        generation = parent[:generation] + 1
      else
        generation = 0
      end

      c =  { contact: contact, parent: parent, generation: generation, sent: false, received: false }

      @contact_generations[generation] ?
          @contact_generations[generation] << c:
          @contact_generations[generation] = [c]
      nil
    end

    def get_unsent_contacts
      ret = []
      @contact_generations.each do |g|
        g.each do |c|
          ret << c unless c[:sent]
        end
      end
      ret
    end

    def add_contacts(contacts, parent)
      raise ArgumentError unless contacts.is_a? Array
      contacts.each do |c|
        add_contact(c, parent)
      end
      nil
    end

    def add_result(from_kad_id, contacts)
      @contact_generations.each do |g|
        parent = g.find { |x| x[:contact].id == from_kad_id }
        if parent
          add_contacts(contacts, parent)
          break
        end
      end
    end
  end

  class KeywordSearch < Search
    attr_reader :keyword
    def initialize(keyword)
      @keyword = keyword
      super(Kademlia::KadID.from_utf8_str(keyword))
    end
  end
end