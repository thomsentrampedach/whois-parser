#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca2'


module Whois
  class Parsers

    # Parser for the whois.nic.tc server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicTc < BaseCocca2
      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts
    end

  end
end
