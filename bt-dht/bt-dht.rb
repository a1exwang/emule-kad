require 'nokogiri'
require 'net/http'
require 'uri'
require 'pp'
# require 'pirata'
require 'base64'
require_relative '../message_queue'
require_relative '../log'
require_relative '../../../../main'


MAX_PAGE = 100

module DHT
  class BTDigg
    def self.instance
      unless @instance
        @instance = BTDigg.new
      end
      @instance
    end
    def self.search_one_page(keyword, page = 0)
      raise ArgumentError, 'invalid page' unless page.is_a?(Integer) && 0 <= page && page < MAX_PAGE
      raise ArgumentError, 'invalid keyword' unless keyword.is_a?(String)

      LOG.logt('search_one_page', "start searching '#{keyword}', page #{page}")
      response = Net::HTTP.get(URI("http://btdigg.org/search?q=#{URI.encode(keyword)}&p=#{page}"))
      h = Nokogiri::HTML(response)
      rows = h.xpath('//div[@id="search_res"]/table/tr')
      results = []
      rows.each do |row|
        columns = row.xpath('td')
        content_table = columns.last
        torrent_name = content_table.xpath('table/tr/td[@class="torrent_name"]//a').first.text
        magnet_uri = content_table.xpath('table').last.xpath('tr/td/a').first.xpath('@href').first.value

        result = { name: torrent_name, uri: magnet_uri }
        content_table.xpath('table').last.xpath('tr/td').each do |td|
          span_attr, span_name = td.xpath('span')
          if span_attr && span_name
            attr = span_attr.text
            name = span_name.text
            result[attr] = name
          end
        end
        results << result
      end

      # pager
      total_pages = 1
      pager_tds = h.xpath('//table[@class="pager"]/tr/td')
      if pager_tds.size > 2
        td = pager_tds[1]
        if td&.text =~ /\d+\/(\d+)/
          total_pages = $1.to_i
        end
      end

      LOG.logt('search_one_page', "keyword '#{keyword}', page #{page}, got #{results.size} results")
      [results, total_pages]
    end
    def search_one_page_async(keyword, page = 0, &callback)
      @queue.add_worker_job do
        results, total_pages = BTDigg.search_one_page(keyword, page)
        @queue << {
            name: 'search_one_page_done',
            callback: callback,
            results: results,
            total_pages: total_pages
        }
      end
    end
    def search_limit_async(keyword, limit = 100, &callback)
      r = Random.rand(0...(2<<64))
      @searches[r] = { keyword: keyword, limit: limit, callback: callback }

      total_results = []
      search_one_page_async(keyword, 0) do |results, total_pages|
        total_results += results
        (1...total_pages).each do |i|
          search_one_page_async(keyword, i) do |res, _|
            total_results += res
            if total_results.size >= limit && callback
              callback.call(total_results)
              callback = nil
              @queue.clear_worker
            end
          end
        end
      end
    end
    def start_blocking
      @queue.start_blocking
    end
    def kill
      @queue.quit
    end
    private
    def initialize
      @queue = Kademlia::MessageQueue.new(20) do |e|
        e.on('search_one_page_done') do |message|
          cb = message[:callback]
          results, total_pages = message[:results], message[:total_pages]
          cb.call(results, total_pages)
        end
      end

      @searches = {}
    end
  end

  module PirateBay
    def get_search_uri(keyword, page)
      URI("https://thepiratebay.org/search/#{URI.encode(keyword)}/#{page}")
    end
    def get_total_pages_by_html(html)

    end
    def get_results_by_html(html)

    end
  end

  module BTDiggWs
    def self.get_search_uri(keyword, page)
      URI("http://btdigg.ws/search/#{Base64.strict_encode64(keyword).gsub('=', '')}/#{page+1}/0/0.html")
    end
    def self.get_total_pages_by_html(html)
      h = Nokogiri::HTML.parse(html.force_encoding('utf-8'))
      ns = h.xpath("//div[@class='bar']").first&.text&.scan(/[0-9.]+/)
      if ns&.size == 3
        count = ns[1].to_i
        count / 20
      else
        0
      end
    end

    def self.parse_js_content(js_content)
      if js_content =~ /document.write\(decodeURIComponent\(([^)]+)\)\)/
        str = $1
        txt = URI.decode_www_form_component(str.gsub(/"|\+/, ''))
        Nokogiri::HTML.parse(txt)
      else
        raise ArgumentError, 'not js content'
      end
    end

    def self.get_results_by_html(html)
      h = Nokogiri::HTML.parse(html.force_encoding('utf-8'))
      results = []
      h.xpath('//dl').each do |dl|
        result = {}
        txt = dl.xpath('dt/a').text
        begin
          html_piece = self.parse_js_content(txt)
          result[:title] = html_piece.xpath('//body').text
        rescue ArgumentError
          result[:title] = txt
        end


        dl.xpath('dd[@class="attr"]').children.each do |span|
          begin
            key, value = span.text.split(':')
          rescue
            key, value = nil, nil
          end

          begin
            magnet_span = parse_js_content(key)
            key = magnet_span.xpath('//body').text
          rescue
            # ignore it
          end

          if key && value
            case key
              when /收录时间/
                result[:added_time] = value
              when /文件大小/
                result[:file_size] = value
              when /文件数/
                result[:file_count] = value.to_i
            end
          elsif key&.include?('磁力链')
            result[:magnet] = magnet_span ? magnet_span.xpath('//a/@href')&.to_s : span.xpath('a/@href').to_s
          end
        end

        results << result
      end

      results
    end
  end

  class Crawler
    SCRAWLER_HTTP_THREAD_COUNT = 32
    def self.instance
      unless @instance
        @instance = Crawler.new
      end
      @instance
    end
    def self.search_one_page(keyword, page = 0)
      raise ArgumentError, 'invalid page' unless page.is_a?(Integer) && 0 <= page && page < MAX_PAGE
      raise ArgumentError, 'invalid keyword' unless keyword.is_a?(String)

      LOG.logt('search_one_page', "start searching '#{keyword}', page #{page}")
      response = Net::HTTP.get(URI("http://btdigg.org/search?q=#{URI.encode(keyword)}&p=#{page}"))
      h = Nokogiri::HTML(response)
      rows = h.xpath('//div[@id="search_res"]/table/tr')
      results = []
      rows.each do |row|
        columns = row.xpath('td')
        content_table = columns.last
        torrent_name = content_table.xpath('table/tr/td[@class="torrent_name"]//a').first.text
        magnet_uri = content_table.xpath('table').last.xpath('tr/td/a').first.xpath('@href').first.value

        result = { name: torrent_name, uri: magnet_uri }
        content_table.xpath('table').last.xpath('tr/td').each do |td|
          span_attr, span_name = td.xpath('span')
          if span_attr && span_name
            attr = span_attr.text
            name = span_name.text
            result[attr] = name
          end
        end
        results << result
      end

      # pager
      total_pages = 1
      pager_tds = h.xpath('//table[@class="pager"]/tr/td')
      if pager_tds.size > 2
        td = pager_tds[1]
        if td&.text =~ /\d+\/(\d+)/
          total_pages = $1.to_i
        end
      end

      LOG.logt('search_one_page', "keyword '#{keyword}', page #{page}, got #{results.size} results")
      [results, total_pages]
    end

    def http_get_cb(uri, &callback)
      @message_queue.add_worker_job do
        html = Net::HTTP.get(uri)
        LOG.logt('http_get_cb', "'#{uri.to_s}' done!")
        @message_queue << {
            name: 'http_get_req_done',
            html: html,
            callback: callback
        }
      end
    end

    def search_one_page_cb(search, current_page, &callback)
      uri = search[:source].get_search_uri(search[:keyword], current_page)
      http_get_cb(uri) do |html|
        pages = search[:source].get_total_pages_by_html(html)
        results = search[:source].get_results_by_html(html)
        callback.call(results, pages)
      end
    end

    def search_page_recur(search, page, &callback)
      search[:pages][page] = []
      search_one_page_cb(search, page) do |results, pages|
        search[:current_count] += results.size
        search[:pages][page] += results
        if search[:current_count] < search[:limit]
          # if the first page is empty or all pages are parsed, we are done.
          # TODO simplify this expression
          if search[:current_count] == 0 ||
              ((search[:pages].map { |page| !page.nil? && !(page.size==0) }.reduce(true, &:&)) &&
                  pages <= search[:pages].size)
            search[:done] =true
            callback.call
          else
            pages.times do |i|
              unless search[:pages][i]
                search_page_recur(search, i, &callback);
              end
            end
          end
        elsif search[:done]
          # do nothing
        else
          search[:done] =true
          callback.call
        end
      end
    end

    def search_async(keyword, limit = 10, source = BTDiggWs, &callback)
      search = {
          keyword: keyword,
          limit: limit,
          pages: [],
          current_count: 0,
          source: source
      }

      search_page_recur(search, 0) do
        results = []
        search[:pages].each do |page|
          page.each do |result|
            results << result[:magnet]
          end
        end
        callback.call(results)
        LOG.logt('btdht', "search_async done #{search[:keyword]}")
      end
    end

    def start_blocking
      @message_queue.start_blocking
    end
    def kill
      @message_queue.quit
    end
    private
    def initialize
      @message_queue = Kademlia::MessageQueue.new(SCRAWLER_HTTP_THREAD_COUNT) do |e|
        e.on('http_get_req_done') do |message|
          callback = message[:callback]
          html = message[:html]
          callback.call(html)
        end
      end

      @searches = {}
    end
  end
end
#
# crawler = DHT::Crawler.instance
# videos = Video.where('designation LIKE ?', 'kawd%').where(status: TASK_STATUS_CREATED)
# count = 0
# videos.each do |video|
#   next if video.links.size > 0
#   count += 1
#   crawler.search_async(video.designation, 10, DHT::BTDiggWs) do |results|
#     results.each do |result|
#       uri_link = UriLink.create(link: result)
#       link = Link.create(film_id: video.id)
#       uri_link.base = link
#       uri_link.save
#       link.real = uri_link
#       link.save
#     end
#     if results.size == 0
#       LOG.logt('add video link', "#{video.designation}: no result!")
#     else
#       LOG.logt('add video link', "#{video.designation}: #{results.size} results!")
#     end
#   end
# end
#
# crawler.start_blocking
#
# LOG.logt('main', "videos total #{count}")
# DHT::BTDiggWs.get_results_by_html(File.read('a.html'))