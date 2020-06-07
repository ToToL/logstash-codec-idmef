# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/idmef"
require "logstash/util/charset"
require 'insist'

describe LogStash::Codecs::IDMEF do

  context "Encode IDMEF" do
    describe "with default configuration" do
      let(:config) { {"paths" => {"alert.messageid" => "67a63ad4-11b9-4ee2-8aee-d1c032a13b35",
                                  "alert.analyzer(0).analyzerid" => "localhost.localdomain"
                                 },
                      "validate_xml" => "true"
                     }
                   }
      subject(:codec) { LogStash::Codecs::IDMEF.new(config) }
    
      let(:expected_result)   { %Q(<?xml version=\"1.0\"?><idmef:IDMEF-Message xmlns:idmef=\"http://iana.org/idmef\"><idmef:Alert messageid=\"67a63ad4-11b9-4ee2-8aee-d1c032a13b35\"><idmef:Analyzer analyzerid=\"localhost.localdomain\"/><idmef:CreateTime ntpstamp=\"0xe274b756.0xc20c49ba\">2020-05-24T09:05:26+00:00</idmef:CreateTime><idmef:DetectTime ntpstamp=\"0xe274b756.0xc20c49ba\">2020-05-24T09:05:26+00:00</idmef:DetectTime><idmef:AnalyzerTime ntpstamp=\"0xe274b756.0xc20c49ba\">2020-05-24T09:05:26+00:00</idmef:AnalyzerTime><idmef:Target decoy=\"unknown\"><idmef:Node category=\"unknown\"><idmef:name>localhost.localdomain</idmef:name></idmef:Node></idmef:Target><idmef:Classification text=\"Login attempt\"/><idmef:AdditionalData meaning=\"@version\" type=\"string\"><idmef:string>1</idmef:string></idmef:AdditionalData></idmef:Alert></idmef:IDMEF-Message>\n)}
      let(:results) { [] }
                          
      it "should return proper IDMEF XML from event" do
        codec.on_event{|data, newdata| results << newdata}
        event = LogStash::Event.new("@timestamp" => DateTime.parse("2020-05-24T09:05:26.758Z").to_time,
                                    "host" => "localhost.localdomain",
                                    "message" => "Login attempt",
                                    "@version" => "1",
                                    "msg" => "")
        codec.encode(event)
        insist {results.first} == expected_result
      end
    end
    
    describe "with additionaldata disabled" do
      let(:config) { {"paths" => {"alert.messageid" => "67a63ad4-11b9-4ee2-8aee-d1c032a13b35",
                                  "alert.analyzer(0).analyzerid" => "localhost.localdomain"
                                 },
                      "validate_xml" => "true",
                      "additionaldata" => "false"
                     }
                   }
      subject(:codec) { LogStash::Codecs::IDMEF.new(config) }
    
      let(:expected_result)   { %Q(<?xml version=\"1.0\"?><idmef:IDMEF-Message xmlns:idmef=\"http://iana.org/idmef\"><idmef:Alert messageid=\"67a63ad4-11b9-4ee2-8aee-d1c032a13b35\"><idmef:Analyzer analyzerid=\"localhost.localdomain\"/><idmef:CreateTime ntpstamp=\"0xe274b756.0xc20c49ba\">2020-05-24T09:05:26+00:00</idmef:CreateTime><idmef:DetectTime ntpstamp=\"0xe274b756.0xc20c49ba\">2020-05-24T09:05:26+00:00</idmef:DetectTime><idmef:AnalyzerTime ntpstamp=\"0xe274b756.0xc20c49ba\">2020-05-24T09:05:26+00:00</idmef:AnalyzerTime><idmef:Target decoy=\"unknown\"><idmef:Node category=\"unknown\"><idmef:name>localhost.localdomain</idmef:name></idmef:Node></idmef:Target><idmef:Classification text=\"Login attempt\"/></idmef:Alert></idmef:IDMEF-Message>\n)}
      let(:results) { [] }
    
      it "should return proper IDMEF XML from event" do
        codec.on_event{|data, newdata| results << newdata}
        event = LogStash::Event.new("@timestamp" => DateTime.parse("2020-05-24T09:05:26.758Z").to_time,
                                    "host" => "localhost.localdomain",
                                    "message" => "Login attempt",
                                    "@version" => "1",
                                    "msg" => "")
        codec.encode(event)
        insist {results.first} == expected_result
      end
    end
    
    describe "with defaults paths disabled" do
      let(:config) { {"paths" => {"alert.messageid" => "67a63ad4-11b9-4ee2-8aee-d1c032a13b35",
                                  "alert.analyzer(0).analyzerid" => "localhost.localdomain",
                                  "alert.create_time" => "%{@timestamp}",
                                  "alert.classification.text" => "%{message}"
                                 },
                      "validate_xml" => "true",
                      "defaults" => "false"
                     }
                   }
      subject(:codec) { LogStash::Codecs::IDMEF.new(config) }
    
      let(:expected_result)   { %Q(<?xml version=\"1.0\"?><idmef:IDMEF-Message xmlns:idmef=\"http://iana.org/idmef\"><idmef:Alert messageid=\"67a63ad4-11b9-4ee2-8aee-d1c032a13b35\"><idmef:Analyzer analyzerid=\"localhost.localdomain\"/><idmef:CreateTime ntpstamp=\"0xe274b756.0xc20c49ba\">2020-05-24T09:05:26+00:00</idmef:CreateTime><idmef:Classification text=\"Login attempt\"/><idmef:AdditionalData meaning=\"host\" type=\"string\"><idmef:string>localhost.localdomain</idmef:string></idmef:AdditionalData><idmef:AdditionalData meaning=\"@version\" type=\"string\"><idmef:string>1</idmef:string></idmef:AdditionalData></idmef:Alert></idmef:IDMEF-Message>\n)}
      let(:results) { [] }
    
      it "should return proper IDMEF XML from event" do
        codec.on_event{|data, newdata| results << newdata}
        event = LogStash::Event.new("@timestamp" => DateTime.parse("2020-05-24T09:05:26.758Z").to_time,
                                    "host" => "localhost.localdomain",
                                    "message" => "Login attempt",
                                    "@version" => "1",
                                    "msg" => "")
        codec.encode(event)
        insist {results.first} == expected_result
      end
    end

    describe "with defaults paths and additionaldata disabled" do
      let(:config) { {"paths" => {"alert.messageid" => "67a63ad4-11b9-4ee2-8aee-d1c032a13b35",
                                  "alert.analyzer(0).analyzerid" => "localhost.localdomain",
                                  "alert.create_time" => "%{@timestamp}",
                                  "alert.classification.text" => "%{message}"
                                 },
                      "validate_xml" => "true",
                      "defaults" => "false",
                      "additionaldata" => "false"
                     }
                   }
      subject(:codec) { LogStash::Codecs::IDMEF.new(config) }
    
      let(:expected_result)   { %Q(<?xml version=\"1.0\"?><idmef:IDMEF-Message xmlns:idmef=\"http://iana.org/idmef\"><idmef:Alert messageid=\"67a63ad4-11b9-4ee2-8aee-d1c032a13b35\"><idmef:Analyzer analyzerid=\"localhost.localdomain\"/><idmef:CreateTime ntpstamp=\"0xe274b756.0xc20c49ba\">2020-05-24T09:05:26+00:00</idmef:CreateTime><idmef:Classification text=\"Login attempt\"/></idmef:Alert></idmef:IDMEF-Message>\n)}
      let(:results) { [] }
    
      it "should return proper IDMEF XML from event" do
        codec.on_event{|data, newdata| results << newdata}
        event = LogStash::Event.new("@timestamp" => DateTime.parse("2020-05-24T09:05:26.758Z").to_time,
                                    "host" => "localhost.localdomain",
                                    "message" => "Login attempt",
                                    "@version" => "1",
                                    "msg" => "")
        codec.encode(event)
        insist {results.first} == expected_result
      end
    end

  end
end
