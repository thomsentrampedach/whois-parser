#!/usr/bin/env ruby -w

d = ARGV.shift

puts `ruby ./utils/mkwhois.rb google.#{d} status_registered`
puts `ruby ./utils/mkwhois.rb fiasodnfiaownf.#{d} status_available`

