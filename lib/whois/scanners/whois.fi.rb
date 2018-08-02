require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.fi record.
    class WhoisFi < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_keyvalue,
          :scan_reserved,
          :ignore_line
      ]


      tokenizer :scan_available do
        if @input.skip(/^Domain not found/)
          @ast["status:available"] = true
        end
      end

      tokenizer :scan_reserved do
        if @input.skip(/^Domain not available/)
          @ast["status:reserved"] = true
        end
      end

      tokenizer :scan_keyvalue do
        if @input.scan(/(.+?):(.*?)(\n|\z)/)
          key, value = @input[1].tr('.', '').strip, @input[2].strip
          target = @tmp['_section'] ? (@ast[@tmp['_section']] ||= {}) : @ast

          if target[key].nil?
            target[key] = value
          else
            target[key] = Array.wrap(target[key])
            target[key] << value
          end
        end
      end

      tokenizer :ignore_line do
        @input.skip(/^([^:]+)\n/)
      end

    end

  end
end
