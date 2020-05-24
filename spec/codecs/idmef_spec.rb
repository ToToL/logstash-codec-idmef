# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/idmef"
require "logstash/util/charset"
require 'insist'

describe LogStash::Codecs::IDMEF do

  context "encode IDMEF" do
    subject(:codec) { LogStash::Codecs::IDMEF.new }

    let(:expected_result)   { %Q(<?xml version=\"1.0\"?><idmef:IDMEF-Message xmlns:idmef=\"http://iana.org/idmef\"><idmef:Alert messageid=\"67a63ad4-11b9-4ee2-8aee-d1c032a13b35\"><idmef:Analyzer analyzerid=\"localhost.localdomain\"/><idmef:CreateTime>2020-05-24T09:05:26+00:00</idmef:CreateTime><idmef:DetectTime>2020-05-24T09:05:26+00:00</idmef:DetectTime><idmef:AnalyzerTime>2020-05-24T09:05:26+00:00</idmef:AnalyzerTime><idmef:Target decoy=\"unknown\"><idmef:Node category=\"unknown\"><idmef:name>localhost.localdomain</idmef:name></idmef:Node></idmef:Target><idmef:Classification text=\"Login attempt\"/><idmef:AdditionalData meaning=\"@version\" type=\"string\"><idmef:string>1</idmef:string></idmef:AdditionalData></idmef:Alert></idmef:IDMEF-Message>\n)}
    let(:results) { []}
                      
    it "should return proper IDMEF XML from event" do
      codec.on_event{|data, newdata| results << newdata}
      codec.paths = {"alert.messageid" => "67a63ad4-11b9-4ee2-8aee-d1c032a13b35" }
      event = LogStash::Event.new("@timestamp" => DateTime.parse("2020-05-24T09:05:26.758Z").to_time, "host" => "localhost.localdomain", "message" => "Login attempt", "@version" => "1", "msg" => "")
      codec.encode(event)
      insist {results.first} == expected_result
    end

  end

end
