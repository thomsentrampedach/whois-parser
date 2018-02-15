require 'spec_helper'
require 'whois/parsers/whois.ripe.net.rb'

describe Whois::Parsers::WhoisRipeNet, "status_registered.expected" do

  subject do
    file = fixture("responses", "whois.ripe.net/status_registered.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#status" do
    it do
      expect(subject.status).to eq(:registered)
    end
  end

  describe "#available?" do
    it do
      expect(subject.available?).to eq(false)
    end
  end

  describe "#registered?" do
    it do
      expect(subject.registered?).to eq(true)
    end
  end

  describe "#created_on" do
    it do
      expect(subject.created_on).to eq(Time.parse('2012-10-17T15:07:44Z'))
    end
  end

  describe "#updated_on" do
    it do
      expect(subject.updated_on).to eq(Time.parse('2016-04-14T10:59:03Z'))
    end
  end

  describe "#expires_on" do
    it do
      expect { subject.expires_on }.to raise_error(Whois::AttributeNotSupported)
    end
  end

  describe "#nameservers" do
    it do
      expect(subject.nameservers).to eq([])
    end
  end

  describe '#response_throttled?' do
    it do
      expect(subject.response_throttled?).to eq(false)
    end
  end

  describe '#registrant_contacts' do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts[0].id).to eq(nil)
      expect(subject.registrant_contacts[0].type).to eq(1)
      expect(subject.registrant_contacts[0].name).to eq(nil)
      expect(subject.registrant_contacts[0].organization).to eq(nil)
      expect(subject.registrant_contacts[0].address).to eq('')
      expect(subject.registrant_contacts[0].city).to eq(nil)
      expect(subject.registrant_contacts[0].zip).to eq(nil)
      expect(subject.registrant_contacts[0].state).to eq(nil)
      expect(subject.registrant_contacts[0].country).to eq(nil)
      expect(subject.registrant_contacts[0].country_code).to eq('PS')
      expect(subject.registrant_contacts[0].phone).to eq(nil)
      expect(subject.registrant_contacts[0].fax).to eq(nil)
      expect(subject.registrant_contacts[0].email)
        .to eq('smansour@palestineix.com')
      expect(subject.registrant_contacts[0].url).to eq(nil)
      expect(subject.registrant_contacts[0].created_on).to eq(nil)
      expect(subject.registrant_contacts[0].updated_on).to eq(nil)
    end
  end

  describe '#admin_contacts' do
    it do
      expect(subject.admin_contacts).to be_a(Array)
      expect(subject.admin_contacts[0].id).to eq(nil)
      expect(subject.admin_contacts[0].type).to eq(2)
      expect(subject.admin_contacts[0].name)
        .to eq('Saleh Mansour')
      expect(subject.admin_contacts[0].organization).to eq(nil)
      expect(subject.admin_contacts[0].address)
        .to eq('NGN Palestine, Ramallah, Palestine <PS>, smansour@ngn.ps')
      expect(subject.admin_contacts[0].country).to eq(nil)
      expect(subject.admin_contacts[0].country_code).to eq('PS')
      expect(subject.admin_contacts[0].phone).to eq('+970-59-9889919')
      expect(subject.admin_contacts[0].fax).to eq('+970-2-2951182')
      expect(subject.admin_contacts[0].email)
        .to eq('smansour@palestineix.com')
      expect(subject.admin_contacts[0].url).to eq(nil)
      expect(subject.admin_contacts[0].created_on).to eq(nil)
      expect(subject.admin_contacts[0].updated_on).to eq(nil)
    end
  end

  describe '#technical_contacts' do
    it do
      expect(subject.technical_contacts).to be_a(Array)
      expect(subject.technical_contacts[0].id).to eq(nil)
      expect(subject.technical_contacts[0].type).to eq(3)
      expect(subject.technical_contacts[0].name)
        .to eq('Saleh Mansour')
      expect(subject.admin_contacts[0].organization).to eq(nil)
      expect(subject.technical_contacts[0].address)
        .to eq('NGN Palestine, Ramallah, Palestine <PS>, smansour@ngn.ps')
      expect(subject.technical_contacts[0].country_code).to eq('PS')
      expect(subject.technical_contacts[0].phone).to eq('+970-59-9889919')
      expect(subject.technical_contacts[0].fax).to eq('+970-2-2951182')
      expect(subject.technical_contacts[0].email)
        .to eq('smansour@palestineix.com')
      expect(subject.technical_contacts[0].url).to eq(nil)
      expect(subject.technical_contacts[0].created_on).to eq(nil)
      expect(subject.technical_contacts[0].updated_on).to eq(nil)
    end
  end
end
