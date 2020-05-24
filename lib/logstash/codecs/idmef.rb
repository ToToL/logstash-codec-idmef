# encoding: utf-8
require "logstash/codecs/base"

require 'socket'
require 'nokogiri'
require 'json'
require 'date'

# Implementation of a Logstash codec for IDMEF based on RFC4765.
# https://tools.ietf.org/html/rfc4765
class LogStash::Codecs::IDMEF < LogStash::Codecs::Base
  config_name "idmef"

  # This parameter let you add IDMEF paths to map from logstash event to IDMEF
  # field.
  # 
  # For example, if:
  # * the name of your alert is in `event.get('message')`
  # * the target host is in `event.get('host')`
  # * the name of your analyzer is "ACME"
  # 
  # you probably want to put this:
  # 
  #     output {
  #       tcp {
  #         codec => idmef {
  #           paths => {
  #             "alert.classification.text" => "$message"
  #             "alert.target(0).node.name" => "$host"
  #             "alert.analyzer(0).name" => "ACME"
  #           }
  #         }
  #         # ...
  #       }
  #     }
  # 
  # The keys of the hash are IDMEF path as described here:
  # https://redmine.secef.net/projects/secef/wiki/LibPrelude_IDMEF_path 
  # 
  # The values of the hash are values to set in final IDMEF. If a value starts with
  # a `$`, then the plugin try to retrieve the value from the event.
  config :paths, :validate => :array, :default => {}

  # Try to use default paths mapping or not.
  # 
  # Default paths are:
  # * alert.classification.text: ["$rule_name", "$event", "$message"]
  # * alert.detect_time: "$@timestamp"
  # * alert.create_time: "$@timestamp"
  # * alert.analyzer_time: "$@timestamp"
  # * alert.analyzer(0).name: ["$product", "$devname"]
  # * alert.analyzer(0).manufacturer: "$vendor"
  # * alert.source(0).node.address(0).address: ["$srcip", "$src"]
  # * alert.source(0).node.name: ["$shost", "$srchost", "$shostname", "$srchostname", "$sname", "$srcname"]
  # * alert.source(0).service.port: ["$spt", "$sport", "$s_port"]
  # * alert.source(0).service.name: ["$sservice", "$srcservice"]
  # * alert.target(0).node.address(0).address: ["$hostip", "$dstip", "$dst", "$ip"]
  # * alert.target(0).node.name: ["$host", "$hostname", "$shost", "$srchost", "$shostname", "$srchostname", "$sname", "$srcname"]
  # * alert.target(0).service.port: ["$dpt", "$dport", "$d_port"]
  # * alert.target(0).service.name: ["$service", "$service_id", "$dservice", "$dstservice",]
  # * alert.target(0).user.user_id(0).name: ["$user", "$dstuser", "$duser"]
  # * alert.target(0).user.user_id(0).number: ["$uid", "$dstuid", "$duid"]
  # * alert.target(0).process.name: ["$proc", "$process"]
  # * alert.target(0).process.pid: ["$dpid", "$pid"]
  # * alert.assessment.impact.severity: ["$severity", "$level"]
  # * alert.assessment.action.description: ["$action"]
  config :defaults, :validate => :boolean, :default => true

  # When an alert is transformed in IDMEF, the remaining fields of the initial
  # event are translated into IDMEF's Additional Data. If you don't want to do this
  # translation, set this setting to `false`.
  config :additionaldata, :validate => :boolean, :default => true

  # IDMEF can defined two types of message:
  # * alert
  # 
  #    RFC definition: Generally, every time an analyzer detects an event that it has
  #    been configured to look for, it sends an Alert message to its manager(s).
  #    Depending on the analyzer, an Alert message may correspond to a single detected
  #    event or multiple detected events. Alerts occur asynchronously in response to
  #    outside events.
  # 
  # * heartbeat
  # 
  #    RFC definition: Analyzers use Heartbeat messages to indicate their current
  #    status to managers.  Heartbeats are intended to be sent in a regular period,
  #    say, every ten minutes or every hour. The receipt of a Heartbeat message from
  #    an analyzer indicates to the manager that the analyzer is up and running; lack
  #    of a Heartbeat message (or more likely, lack of some number of consecutive
  #    Heartbeat messages) indicates that the analyzer or its network connection has
  #    failed.
  config :type, :validate => :string, :default => "alert"

  # RFC 4765: UserID Class
  IDMEFUserId = { :type => :class,
                  :name => "UserId",
                  "name" => { :type => :list_value, :name => "name" },
                  "type" => { :type => :attr, :name => "type", :default => "original-user" },
                  "tty" => { :type => :attr, :name => "tty" },
                  "number" => { :type => :list_value, :name => "number" }
                }
  
  # RFC 4765: User Class
  IDMEFUser = { :type => :class,
                :name => "User",
                "category" => { :type => :attr, :name => "category", :default => "unknown" },
                "user_id" => { :type => :list_class, :class => IDMEFUserId }
              }
  
  # RFC 4765: FileAccess Class
  IDMEFFileAccess = { :type => :class,
                      :name => "FileAccess",
                      "user_id" => { :type => :list_class, :class => IDMEFUserId }
                    }
  
  # RFC 4765: File Class
  IDMEFFile = { :type => :class,
                :name => "File",
                "category" => { :type => :attr, :name => "category" },
                "fstype" => { :type => :attr, :name => "fstype" },
                "file-type" => { :type => :attr, :name => "file-type" },
                "name" => { :type => :list_value, :name => "name" },
                "path" => { :type => :list_value, :name => "path" },
                "file_access" => { :type => :list_class, :class => IDMEFFileAccess }
              }
  
  # RFC 4765: WebService Class
  IDMEFWebService = { :type => :class,
                      :name => "WebService",
                      "url" => { :type => :list_value, :name => "url" }
                    }
  
  # RFC 4765: SNMPService Class
  IDMEFSNMPService = { :type => :class,
                       :name => "SNMPService",
                       "command" => { :type => :list_value, :name => "command" }
                     }
  
  # RFC 4765: Service Class
  IDMEFService = { :type => :class,
                   :name => "Service",
                   "ip_version" => { :type => :attr, :name => "ip_version" },
                   "iana_protocol_number" => { :type => :attr, :name => "iana_protocol_number" },
                   "iana_protocol_name" => { :type => :attr, :name => "iana_protocol_name" },
                   "name" => { :type => :list_value, :name => "name" },
                   "port" => { :type => :list_value, :name => "port" },
                   "portlist" => { :type => :list_value, :name => "portlist" },
                   "protocol" => { :type => :list_value, :name => "protocol" },
                   "web_service" => { :type => :list_class, :class => IDMEFWebService },
                   "snmp_service" => { :type => :list_class, :class => IDMEFSNMPService }
                 }
  
  # RFC 4765: Address Class
  IDMEFAddress = { :type => :class,
                   :name => "Address",
                   "category" => { :type => :attr, :name => "category", :default => "unknown" },
                   "vlan-name" => { :type => :attr, :name => "vlan-name" },
                   "vlan-num" => { :type => :attr, :name => "vlan-num" },
                   "address" => { :type => :list_value, :name => "address" },
                   "netmask" => { :type => :list_value, :name => "netmask" },
                 }
  
  # RFC 4765: Node Class
  IDMEFNode = { :type => :class,
                :name => "Node",
                "category" => { :type => :attr, :name => "category", :default => "unknown" },
                "location" => { :type => :list_value, :name => "location" },
                "name" => { :type => :list_value, :name => "name" },
                "address" => { :type => :list_class, :class => IDMEFAddress },
              }
  
  # RFC 4765: Process Class
  IDMEFProcess = { :type => :class,
                   :name => "Process",
                   "name" => { :type => :list_value, :name => "name" },
                   "pid" => { :type => :list_value, :name => "pid" },
                   "path" => { :type => :list_value, :name => "path" },
                   "arg" => { :type => :list_value, :name => "arg" },
                   "env" => { :type => :list_value, :name => "env" },
                 }
  
  # RFC 4765: Analyzer Class
  IDMEFAnalyzer = { :type => :class,
                    :name => "Analyzer",
                    "analyzerid" => { :type => :attr, :name => "analyzerid" },
                    "name" => { :type => :attr, :name => "name" },
                    "manufacturer" => { :type => :attr, :name => "manufacturer" },
                    "model" => { :type => :attr, :name => "model" },
                    "version" => { :type => :attr, :name => "version" },
                    "class" => { :type => :attr, :name => "class" },
                    "ostype" => { :type => :attr, :name => "ostype" },
                    "osversion" => { :type => :attr, :name => "osversion" },
                    "node" => { :type => :list_class, :class => IDMEFNode },
                    "process" => { :type => :list_class, :class => IDMEFProcess },
                  }
  IDMEFAnalyzer["analyzer"] = { :type => :list_class, :class => IDMEFAnalyzer }
  
  # RFC 4765: Source Class
  IDMEFSource = { :type => :class,
                  :name => "Source",
                  "spoofed" => { :type => :attr, :name => "spoofed", :default => "unknown" },
                  "interface" => { :type => :attr, :name => "interface" },
                  "node" => { :type => :list_class, :class => IDMEFNode },
                  "user" => { :type => :list_class, :class => IDMEFUser },
                  "process" => { :type => :list_class, :class => IDMEFProcess },
                  "service" => { :type => :list_class, :class => IDMEFService },
                }
  
  # RFC 4765: Target Class
  IDMEFTarget = { :type => :class,
                  :name => "Target",
                  "decoy" => { :type => :attr, :name => "decoy", :default => "unknown" },
                  "interface" => { :type => :attr, :name => "interface" },
                  "node" => { :type => :list_class, :class => IDMEFNode },
                  "user" => { :type => :list_class, :class => IDMEFUser },
                  "process" => { :type => :list_class, :class => IDMEFProcess },
                  "service" => { :type => :list_class, :class => IDMEFService },
                  "file" => { :type => :list_class, :class => IDMEFFile }
                }
  
  # RFC 4765: Impact Class
  IDMEFImpact = { :type => :class,
                  :name => "Impact",
                  "severity" => { :type => :attr, :name => "severity" },
                  "completion" => { :type => :attr, :name => "completion" },
                  "type" => { :type => :attr, :name => "type", :default => "other" },
                }
  
  # RFC 4765: Action Class
  IDMEFAction = { :type => :class,
                  :name => "Action",
                  "category" => { :type => :attr, :name => "category", :default => "other" },
                  "description" => { :type => :value },
                }
  
  # RFC 4765: Confidence Class
  IDMEFConfidence = { :type => :class,
                      :name => "Confidence",
                      "rating" => { :type => :attr, :name => "rating", :default => "numeric" },
                      "confidence" => { :type => :value },
                    }
  
  # RFC 4765: Reference Class
  IDMEFReference = { :type => :class,
                     :name => "Reference",
                     "origin" => { :type => :attr, :name => "origin", :default => "unknown" },
                     "meaning" => { :type => :attr, :name => "meaning" },
                     "name" => { :type => :list_value, :name => "name" },
                     "url" => { :type => :list_value, :name => "url" }
                   }
  
  # RFC 4765: AdditionalData Class
  IDMEFAdditionalData = { :type => :class,
                          :name => "AdditionalData",
                          "meaning" => { :type => :attr, :name => "meaning" },
                          "type" => { :type => :attr, :name => "type" },
                          "data" => { :type => :list_value, :name => :type }
                        }
  # RFC 4765: CorrelationAlert Class
  IDMEFCorrelationAlert = { :type => :class,
                            :name => "CorrelationAlert",
                            "name" => { :type => :list_value, :name => "name" },
                            "alertident" => { :type => :list_value, :name => "alertident" }
                          }
  
  # RFC 4765: Assessment Class
  IDMEFAssessment = { :type => :class,
                      :name => "Assessment",
                      "impact" => { :type => :list_class, :class => IDMEFImpact },
                      "action" => { :type => :list_class, :class => IDMEFAction },
                      "confidence" => { :type => :list_class, :class => IDMEFConfidence }
                    }
  
  # RFC 4765: Classification Class
  IDMEFClassification = { :type => :class,
                          :name => "Classification",
                          "text" => { :type => :attr, :name => "text" },
                          "reference" => { :type => :list_class, :class => IDMEFReference }
                        }
  
  # RFC 4765: Alert Class
  IDMEFAlert = { :type => :class,
                 :name => "Alert",
                 "messageid" => { :type => :attr, :name => "messageid" },
                 "create_time" => { :type => :list_value, :name => "CreateTime", :format => :datetime},
                 "detect_time" => { :type => :list_value, :name => "DetectTime", :format => :datetime },
                 "analyzer_time" => { :type => :list_value, :name => "AnalyzerTime", :format => :datetime },
                 "analyzer" => { :type => :list_class, :class => IDMEFAnalyzer },
                 "classification" => { :type => :list_class, :class => IDMEFClassification },
                 "source" => { :type => :list_class, :class => IDMEFSource },
                 "target" => { :type => :list_class, :class => IDMEFTarget },
                 "assessment" => { :type => :list_class, :class => IDMEFAssessment },
                 "additional_data" => { :type => :list_class, :class => IDMEFAdditionalData },
                 "correlation_alert" => { :type => :list_class, :class => IDMEFCorrelationAlert },
               }
  
  # RFC 4765: Message Class
  IDMEFMessage = { :type => :class,
                   :name => "IDMEF-Message",
                   "alert" => { :type => :list_class, :class => IDMEFAlert },
                 }
  private
  def idmefpaths_to_xml(event, paths, doc = nil)
      if doc.nil?
          doc = Nokogiri::XML::Document.new
          doc.root = Nokogiri::XML::Node.new('IDMEF-Message', doc)
          doc.root.add_namespace_definition('idmef', 'http://iana.org/idmef')
      end
      event_to_remove = []
      paths.each do |path, value|
          if !value.kind_of?(Array)
            value = [value]
          end
          value.each do |v|
            if v.to_s.start_with?("$")
                  c = ''
                  f = true
                  v[1..-1].split('.').each do |ppath|
                    if !event.get(c + '[' + ppath + ']').nil?
                      c = c + '[' + ppath + ']'
                    else
                      f = false
                    end
                  end
                  if !f then next end
                  value = event.get(c)
                  event_to_remove << c
              else
                  value = v
              end
          end
          if value.kind_of?(Array) or value.to_s.empty?
              next
          end
          if value.kind_of?(String)
              @utf8_charset.convert(value)
          end
          curr = doc.root
          rfc = IDMEFMessage
          path.split('.').each do |name|
              ret = name.match(/^(.*)\((\d+)\)/)
              if ret
                 name = ret[1]
                 v = (ret ? ret[2] : 0).to_i
              end
  
              ne = rfc[name][:class]
              ne_t = rfc[name][:type]
              path_idmef = rfc[name][:type] == :list_class ? ne[:name] : nil
  
              if ret && ne_t == :list_class
                 c = curr.xpath(path_idmef)
                 if c.empty?
                     no = Nokogiri::XML::Node.new(ne[:name], doc)
                     curr << no
                 elsif c.length <= v
                     nod = c[-1]
                     (c.length..v).each do |t|
                         no = Nokogiri::XML::Node.new(ne[:name], doc)
                         nod.after(no)
                         nod = no
                     end
                 elsif c.length > v
                     no = c[v]
                 end
                 curr = no
                 rfc = ne
              elsif !ret && ne_t == :list_class
                 no = curr.xpath(path_idmef).first || Nokogiri::XML::Node.new(ne[:name], doc)
                 curr << no
                 curr = no
                 rfc = ne
              elsif ne_t == :list_value
                 if rfc[name][:format] == :datetime
                   value = DateTime.parse(value.to_s).strftime("%FT%T%:z")
                 end
                 n = rfc[name][:name] == :type ? curr["type"] : rfc[name][:name]
                 no = Nokogiri::XML::Node.new(n, doc)
                 no.content = value.to_s
                 curr << no
              elsif ne_t == :attr
                 if rfc[name][:format] == :datetime
                   value = DateTime.parse(value.to_s).strftime("%FT%T%:z")
                 end
                 curr[rfc[name][:name]] = value.to_s
              end
              rfc.each do |kk, vv|
                  if vv.respond_to?(:each_pair) && vv[:default] && vv[:type] == :attr && !curr[vv[:name]]
                      curr[vv[:name]] = vv[:default]
                  end
              end
          end
      end
      event_to_remove.each do |v|
        event.remove(v)
      end
      return doc
  end

  private
  def xml_to_string(doc)
      doc.root.traverse { |node| 
        if node.type != Nokogiri::XML::Node::TEXT_NODE
          node.name = 'idmef:' + node.name
        end
      }
      return doc.serialize(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML).sub("\n", "").strip
  end

  public
  def initialize(params={})
    super(params)
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger

    @local_paths = {
      "alert.analyzer(0).name" => ["$product", "$devname"],
      "alert.analyzer(0).manufacturer" => "$vendor",
      "alert.create_time" => "$@timestamp",
      "alert.detect_time" => "$@timestamp",
      "alert.analyzer_time" => "$@timestamp",
      "alert.source(0).node.address(0).address" => ["$srcip", "$src"],
      "alert.source(0).node.name" => ["$shost", "$srchost", "$shostname", "$srchostname", "$sname", "$srcname"],
      "alert.source(0).service.port" => ["$spt", "$sport", "$s_port"],
      "alert.source(0).service.name" => ["$sservice", "$srcservice"],
      "alert.target(0).node.address(0).address" => ["$hostip", "$dstip", "$dst", "$ip"],
      "alert.target(0).node.name" => ["$host", "$hostname", "$shost", "$srchost", "$shostname", "$srchostname", "$sname", "$srcname"],
      "alert.target(0).service.port" => ["$dpt", "$dport", "$d_port"],
      "alert.target(0).service.name" => ["$service", "$service_id", "$dservice", "$dstservice",],
      "alert.target(0).user.user_id(0).name" => ["$user", "$dstuser", "$duser"],
      "alert.target(0).user.user_id(0).number" => ["$uid", "$dstuid", "$duid"],
      "alert.target(0).process.name" => ["$proc", "$process"],
      "alert.target(0).process.pid" => ["$dpid", "$pid"],
      "alert.classification.text" => ["$rule_name", "$event", "$message"],
      "alert.assessment.impact.severity" => ["$severity", "$level"],
      "alert.assessment.action.description" => ["$action"],
    }
    if @defaults
      @allpaths = @local_paths.merge(@paths)
    else
      @allpaths = @paths
    end
  end

  public
  def encode(event)
    # Reload configuration
    @allpaths = @allpaths.merge(@paths)

    # Copy event
    e = event.clone

    # Set messageid and analyzerid
    p = { "%s.messageid" % @type => java.util.UUID.randomUUID.to_s,
          "%s.analyzer(0).analyzerid" % @type => Socket.gethostname.to_s
        }
    xml = idmefpaths_to_xml(e, p)
    
    # Set paths
    xml = idmefpaths_to_xml(e, @allpaths, xml)

    # Set Additional data
    if @additionaldata
      idx = xml.xpath('/IDMEF-Message/Alert/AddionnalData').length
      e.to_hash.each do |key, value|
        if value.kind_of?(Integer)
          t = "integer"
        elsif value.kind_of?(Float)
          t = "real"
        else
          t = "string"
        end
        p = { "alert.additional_data(%d).meaning" % idx => key,
              "alert.additional_data(%d).type" % idx => t,
              "alert.additional_data(%d).data" % idx => value.to_s,
            }
        xml = idmefpaths_to_xml(e, p , xml)
        idx = idx + 1
      end
    end

    # Create the XML
    @on_event.call(event, xml_to_string(xml) + NL)
  end

end
