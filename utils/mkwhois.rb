#!/usr/bin/env ruby -w

# Usage:
#
# $ ./utils/mkwhois.rb google.com.br status_registered
#
# It will execute the query and dump the result into a file
# called status_registered.txt into the appriate folder based
# on the hostname that was queried, and the TLD.

$:.unshift(File.expand_path("../../lib", __FILE__))

require 'fileutils'
require 'whois'
begin
  require File.expand_path("../whois-utf8", __FILE__)
rescue LoadError
end

d = ARGV.shift || raise("Missing domain")
n = ARGV.shift || raise("Missing file name")

r = Whois.lookup(d)
tld = r.server.allocation

def classify(string)
  string.split('/').collect do |c|
    c.split(/_|\.|-/).collect(&:capitalize).join
  end.join('::')
end

r.parts.each do |part|
  next if part.host == 'whois.verisign-grs.com'

  target = File.expand_path("../../spec/fixtures/responses/#{part.host}/#{tld}/#{n}.txt", __FILE__)
  FileUtils.mkdir_p(File.dirname(target))
  File.open(target, "w+") { |f| f.write(part.body) }
  puts "Response: #{target}"

  target = File.expand_path("../../lib/whois/parsers/#{part.host}.rb", __FILE__)
  text = <<~EOF
require_relative 'base_icann_compliant'
module Whois
  class Parsers
    class #{classify(part.host)} < BaseIcannCompliant
      # self.scanner = Scanners::BaseIcannCompliant, {
      #   pattern_available: /DOMAIN NOT FOUND/
      #   pattern_disclaimer: /^Access to/,
      #   pattern_throttled: /^WHOIS LIMIT EXCEEDED/,
      # }
    end
  end
end
  EOF
  File.open(target, "w+") { |f| f.write(text) }
  puts "Parser File: #{target}"
end

# results = {}
# CSV.foreach('./utils/whoisservertodo_with_domain.csv', :headers => true) do |row|
#   results[row['host']] ||= { domains: [], count: 0 }
#   results[row['host']][:domains] << row['domain']
#   results[row['host']][:count] += 1
# end
