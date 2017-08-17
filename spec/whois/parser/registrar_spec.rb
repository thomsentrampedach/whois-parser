require 'spec_helper'
require 'whois/parser/registrar'


describe Whois::Parser::Registrar do

  it "inherits from SuperStruct" do
    expect(described_class.ancestors).to include(SuperStruct)
  end


  describe "#initialize" do
    it "accepts an empty value" do
      expect {
        instance = described_class.new
        expect(instance.id).to be_nil
      }.to_not raise_error
    end

    it "accepts an empty hash" do
      expect {
        instance = described_class.new({})
        expect(instance.id).to be_nil
      }.to_not raise_error
    end

    it "initializes a new instance from given hash" do
      instance = described_class.new(
        :id => 10,
        :name => "John Doe",
        :url => "http://example.com",
        :email => "test@example.com",
        :phone => "+15555555555"
      )

      expect(instance.id).to eq(10)
      expect(instance.name).to eq("John Doe")
      expect(instance.organization).to be_nil
      expect(instance.url).to eq("http://example.com")
      expect(instance.email).to eq("test@example.com")
      expect(instance.phone).to eq("+15555555555")
    end

    it "initializes a new instance from given block" do
      instance = described_class.new do |c|
        c.id    = 10
        c.name  = "John Doe"
        c.url   = "http://example.com"
      end

      expect(instance.id).to eq(10)
      expect(instance.name).to eq("John Doe")
      expect(instance.organization).to be_nil
      expect(instance.url).to eq("http://example.com")
    end
  end

end
