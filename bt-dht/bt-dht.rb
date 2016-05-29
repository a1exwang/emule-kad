require 'nokogiri'
require 'net/http'
require 'uri'
require 'pp'
require_relative '../message_queue'
require_relative '../log'

MAX_PAGE = 100

module DHT
  class BTDigg
    def initialize
      @queue = Kademlia::MessageQueue.new do |e|
        e.on('search_one_page_done') do |message|
          cb = message[:callback]
          results, total_pages = message[:results], message[:total_pages]
          cb.call(results, total_pages)
        end
      end
    end
    def search_one_page(keyword, page = 0)
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

    def search_one_page_async(keyword, page = 0, &block)
      @queue.add_worker_job do
        results, total_pages = search_one_page(keyword, page)
        @queue << {
            name: 'search_one_page_done',
            callback: block,
            results: results,
            total_pages: total_pages
        }
      end
    end

    def search_limit_async(keyword, limit = 100, &block)
      total_results = []
      search_one_page_async(keyword, 0) do |results, total_pages|
        total_results += results
        (1...total_pages).each do |i|
          search_one_page_async(keyword, i) do |res, _|
            total_results += res
            if total_results.size >= limit
              block.call(total_results)
              @queue.quit
            end
          end
        end
      end
    end

    def start_blocking
      @queue.start_blocking
    end

  end

end

btdigg = DHT::BTDigg.new

btdigg.search_limit_async('abc', 100) do |results|
  puts results
end

btdigg.start_blocking


