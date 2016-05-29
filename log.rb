
module Kademlia
  module Utils
    class Logger
      TAG_MAX_WIDTH = 16
      def initialize(target = nil, attr = 'w', use_lock = true)
        if target.is_a?(String)
          @stream = File.open(target, attr)
        else
          @stream = STDOUT
        end
        level_map = {
            verbose: 'V',
            normal:  'N',
            debug:   'D'
        }
        # this is default formatter
        set_format do |tag, str, indent, level|
          lines = str.split("\n")
          result = ''
          lines.each_with_index do |line, index|
            # -V timestamp tag indent*' ' str
            result += "-%s %s %-#{TAG_MAX_WIDTH}s%-#{indent+4 + (index == 0 ? 0 : 2)}s%s\n" %
                [level_map[level],
                 Time.now.strftime('%H:%M:%S.%6N'),
                 tag[0, TAG_MAX_WIDTH],
                 '', # indent
                 line]
          end
          result
        end
        if use_lock
          @lock = Mutex.new
        end
      end
      def set_format(&block)
        raise ArgumentError unless block
        @formatter = block
      end
      def log(str, indent = 0, level = 'verbose'.to_sym)
        raise ArgumentError unless indent.is_a?(Integer) && (level.is_a?(String) || level.is_a?(Symbol))
        logt('', str, indent, level)
      end
      def logt(tag, str, indent = 0, level = 'verbose'.to_sym)
        str = @formatter.call(tag, str, indent, level)
        @lock&.lock

        @stream.write(str)
        @stream.flush

        @lock&.unlock
      end
    end
  end
end

LOG = Kademlia::Utils::Logger.new