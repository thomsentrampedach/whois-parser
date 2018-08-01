#!/usr/bin/env ruby -w
#
d = ARGV.shift

`ruby ./utils/mkwhois google.#{d} status_registered`
`ruby ./utils/mkwhois fiasodnfiaownf.#{d} status_available`

