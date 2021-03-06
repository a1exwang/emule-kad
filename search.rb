require_relative 'kad_id'
require 'uri'

module Kademlia

  class Search
    attr_reader :id
    attr_reader :search_uid
    def initialize(id)
      @id = id
      @search_uid = Time.now.strftime('search-%Y-%m-%d_%H_%M_%S.%6N-') + (0...10).map { ('a'..'z').to_a[Random.rand(26)] }.join
    end
  end

  ##
  # NodeIDSearch
  # @contact_generations数组保存了最多KadID::BIT_WIDTH代数的contact数组
  # 代(generation)的定义为:
  #   1.自己为第-1代中的唯一元素;
  #   2. 对第i代中的contact发送查询请求, 得到的结果集合为第i+1代
  class NodeIDSearch < Search
    FIND_NODE_COUNT = 0xb
    def initialize(id, init_contacts)
      super(id)
      @contact_generations = []
      init_contacts.each do |c|
        add_contact(c)
      end
    end

    def add_contact_by_parent_id(contact, parent_id)
      if parent_id.nil?
        add_contact(contact)
        return
      end

      @contact_generations.each_with_index do |g, i|
        g.each do |c|
          if c[:contact].id == parent_id
            add_contact(contact, c)
            return
          end
        end
      end
      raise ArgumentError, "parent id '#{parent_id} not found"
    end

    def log_self
      LOG.logt('search result', "search generation: #{@contact_generations.size.to_s}, id '#{@id}'")
      @contact_generations.last.each do |c|
        contact = c[:contact]
        LOG.logt('search result', "dis: #{(@id ^ contact.id).highest_one}bits, id :#{contact.id}", 4)
      end
    end

    def find_contact(kad_id)
      @contact_generations.each do |g|
        g.each do |c|
          if c[:contact].id == kad_id
            return c
          end
        end
      end
      nil
    end

    ##
    #
    def add_contact(contact, parent = nil)
      # return if find_contact(contact.id)
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

    ##
    # get all contacts to whom we have not sent find-node request,
    #   and mark them 'sent'
    # this function returns +max+ results that are nearest to target
    def get_unsent_contacts_and_set_sent(max = FIND_NODE_COUNT)
      ret = []
      @contact_generations.each do |g|
        g.each do |c|
          unless c[:sent]
            ret << c
            c[:sent] = true
          end
        end
      end
      ret.sort do |x, y|
        (x[:contact].id ^ @id) <=> (y[:contact].id ^ @id)
      end.first(max)
    end

    def get_closest_contacts
      ret = []
      @contact_generations.each do |g|
        g.each do |c|
          ret << c
        end
      end
      ret.sort do |x, y|
        (x[:contact].id ^ @id) <=> (y[:contact].id ^ @id)
      end
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

  class KeywordSearch < NodeIDSearch
    attr_reader :keyword
    attr_reader :last_search_res_at
    attr_reader :results
    attr_accessor :saved
    attr_accessor :finished_callbacks
    attr_reader :done

    def initialize(keyword, init_contacts)
      @keyword = keyword
      @saved = false
      @last_search_res_at = Time.now
      @results = {}
      @finished_callbacks = []
      @done = false
      super(Kademlia::KadID.from_utf8_str(keyword), init_contacts)
    end

    def add_search_res(result)
      @last_search_res_at = Time.now
      if @results[result[:sender_id]]
        @results[result[:sender_id]] << result[:answers]
      else
        @results[result[:sender_id]] = result[:answers]
      end
    end

    def search_name
      "S_#{@keyword}_uid_#{@search_uid}"
    end

    def to_json(state = nil)
      {
          name: search_name,
          keyword: @keyword,
          id: @id,
          results: @results
      }.to_json(state)
    end

    def add_finished_callback(cb)
      if cb
        @finished_callbacks << cb
      end
    end

    def done?
      @done
    end

    def need_on_finished?
      !@done && Time.now - @last_search_res_at > 10
    end

    def on_finished
      @done = true
      @finished_callbacks.each do |cb|
        cb.call(self)
      end
    end

    def results_ed2k
      ed2ks = []
      @results.each do |sender_id, answers|
        answers.each do |a|
          file_name = URI.encode(a[:tags]['file_name'])
          file_size = a[:tags]['file_size'] || 100000000
          hash = a[:answer].to_s_ed2k
          ed2ks << "ed2k://|file|#{file_name}|#{file_size}|#{hash}|/"
        end
      end
      ed2ks
    end

  end
end