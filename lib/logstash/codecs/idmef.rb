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
  #             "alert.classification.text" => "%{message}"
  #             "alert.target(0).node.name" => "%{host}"
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
  # The values of the hash are values to set in final IDMEF. If there is
  # %{name} inside the string, the plugin try to retrieve the value from
  # the event and create the final string.
  config :paths, :validate => :array, :default => {}

  # Try to use default paths mapping or not.
  # 
  # Default paths are:
  # * "alert.analyzer(0).name": ["%{product}", "%{devname}"]
  # * "alert.analyzer(0).manufacturer": ["%{vendor}"]
  # * "alert.create_time": ["%{@timestamp}"]
  # * "alert.detect_time": ["%{@timestamp}"]
  # * "alert.analyzer_time": ["%{@timestamp}"]
  # * "alert.source(0).node.address(0).address": ["%{srcip}", "%{src}"]
  # * "alert.source(0).node.name": ["%{shost}", "%{srchost}", "%{shostname}", "%{srchostname}", "%{sname}", "%{srcname}"]
  # * "alert.source(0).service.port": ["%{spt}", "%{sport}", "%{s_port}"]
  # * "alert.source(0).service.name": ["%{sservice}", "%{srcservice}"]
  # * "alert.target(0).node.address(0).address": ["%{hostip}", "%{dstip}", "%{dst}", "%{ip}"]
  # * "alert.target(0).node.name": ["%{host}", "%{hostname}", "%{shost}", "%{srchost}", "%{shostname}", "%{srchostname}", "%{sname}", "%{srcname}"]
  # * "alert.target(0).service.port": ["%{dpt}", "%{dport}", "%{d_port}"]
  # * "alert.target(0).service.name": ["%{service}", "%{service_id}", "%{dservice}", "%{dstservice}"]
  # * "alert.target(0).user.user_id(0).name": ["%{user}", "%{dstuser}", "%{duser}"]
  # * "alert.target(0).user.user_id(0).number": ["%{uid}", "%{dstuid}", "%{duid}"]
  # * "alert.target(0).process.name": ["%{proc}", "%{process}"]
  # * "alert.target(0).process.pid": ["%{dpid}", "%{pid}"]
  # * "alert.classification.text": ["%{rule_name}", "%{event}", "%{message}"]
  # * "alert.assessment.impact.severity": ["%{severity}", "%{level}"]
  # * "alert.assessment.action.description": ["%{action}"]
  config :defaults, :validate => :boolean, :default => true

  # When an alert is transformed in IDMEF, the remaining fields of the initial
  # event are translated into IDMEF's Additional Data. If you don't want to do this
  # translation, set this setting to `false`.
  config :additionaldata, :validate => :boolean, :default => true

  # Validate the generated XML with IDMEF DTD.
  config :validate_xml, :validate => :boolean, :default => false

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

  @@IDMEF_Time_Format = "%FT%T%:z"

  # RFC 4765: UserID Class
  @@IDMEFUserId = { :type => :class,
                  :name => "UserId",
                  "name" => { :type => :list_value, :name => "name" },
                  "type" => { :type => :attr, :name => "type", :default => "original-user" },
                  "tty" => { :type => :attr, :name => "tty" },
                  "number" => { :type => :list_value, :name => "number" }
                }
  
  # RFC 4765: User Class
  @@IDMEFUser = { :type => :class,
                :name => "User",
                "category" => { :type => :attr, :name => "category", :default => "unknown" },
                "user_id" => { :type => :list_class, :class => @@IDMEFUserId }
              }
  
  # RFC 4765: FileAccess Class
  @@IDMEFFileAccess = { :type => :class,
                      :name => "FileAccess",
                      "user_id" => { :type => :list_class, :class => @@IDMEFUserId }
                    }
  
  # RFC 4765: File Class
  @@IDMEFFile = { :type => :class,
                :name => "File",
                "category" => { :type => :attr, :name => "category" },
                "fstype" => { :type => :attr, :name => "fstype" },
                "file-type" => { :type => :attr, :name => "file-type" },
                "name" => { :type => :list_value, :name => "name" },
                "path" => { :type => :list_value, :name => "path" },
                "file_access" => { :type => :list_class, :class => @@IDMEFFileAccess }
              }
  
  # RFC 4765: WebService Class
  @@IDMEFWebService = { :type => :class,
                      :name => "WebService",
                      "url" => { :type => :list_value, :name => "url" }
                    }
  
  # RFC 4765: SNMPService Class
  @@IDMEFSNMPService = { :type => :class,
                       :name => "SNMPService",
                       "command" => { :type => :list_value, :name => "command" }
                     }
  
  # RFC 4765: Service Class
  @@IDMEFService = { :type => :class,
                   :name => "Service",
                   "ip_version" => { :type => :attr, :name => "ip_version" },
                   "iana_protocol_number" => { :type => :attr, :name => "iana_protocol_number" },
                   "iana_protocol_name" => { :type => :attr, :name => "iana_protocol_name" },
                   "name" => { :type => :list_value, :name => "name" },
                   "port" => { :type => :list_value, :name => "port" },
                   "portlist" => { :type => :list_value, :name => "portlist" },
                   "protocol" => { :type => :list_value, :name => "protocol" },
                   "web_service" => { :type => :list_class, :class => @@IDMEFWebService },
                   "snmp_service" => { :type => :list_class, :class => @@IDMEFSNMPService }
                 }
  
  # RFC 4765: Address Class
  @@IDMEFAddress = { :type => :class,
                   :name => "Address",
                   "category" => { :type => :attr, :name => "category", :default => "unknown" },
                   "vlan-name" => { :type => :attr, :name => "vlan-name" },
                   "vlan-num" => { :type => :attr, :name => "vlan-num" },
                   "address" => { :type => :list_value, :name => "address" },
                   "netmask" => { :type => :list_value, :name => "netmask" },
                 }
  
  # RFC 4765: Node Class
  @@IDMEFNode = { :type => :class,
                :name => "Node",
                "category" => { :type => :attr, :name => "category", :default => "unknown" },
                "location" => { :type => :list_value, :name => "location" },
                "name" => { :type => :list_value, :name => "name" },
                "address" => { :type => :list_class, :class => @@IDMEFAddress },
              }
  
  # RFC 4765: Process Class
  @@IDMEFProcess = { :type => :class,
                   :name => "Process",
                   "name" => { :type => :list_value, :name => "name" },
                   "pid" => { :type => :list_value, :name => "pid" },
                   "path" => { :type => :list_value, :name => "path" },
                   "arg" => { :type => :list_value, :name => "arg" },
                   "env" => { :type => :list_value, :name => "env" },
                 }
  
  # RFC 4765: Analyzer Class
  @@IDMEFAnalyzer = { :type => :class,
                    :name => "Analyzer",
                    "analyzerid" => { :type => :attr, :name => "analyzerid" },
                    "name" => { :type => :attr, :name => "name" },
                    "manufacturer" => { :type => :attr, :name => "manufacturer" },
                    "model" => { :type => :attr, :name => "model" },
                    "version" => { :type => :attr, :name => "version" },
                    "class" => { :type => :attr, :name => "class" },
                    "ostype" => { :type => :attr, :name => "ostype" },
                    "osversion" => { :type => :attr, :name => "osversion" },
                    "node" => { :type => :list_class, :class => @@IDMEFNode },
                    "process" => { :type => :list_class, :class => @@IDMEFProcess },
                  }
  @@IDMEFAnalyzer["analyzer"] = { :type => :list_class, :class => @@IDMEFAnalyzer }
  
  # RFC 4765: Source Class
  @@IDMEFSource = { :type => :class,
                  :name => "Source",
                  "spoofed" => { :type => :attr, :name => "spoofed", :default => "unknown" },
                  "interface" => { :type => :attr, :name => "interface" },
                  "node" => { :type => :list_class, :class => @@IDMEFNode },
                  "user" => { :type => :list_class, :class => @@IDMEFUser },
                  "process" => { :type => :list_class, :class => @@IDMEFProcess },
                  "service" => { :type => :list_class, :class => @@IDMEFService },
                }
  
  # RFC 4765: Target Class
  @@IDMEFTarget = { :type => :class,
                  :name => "Target",
                  "decoy" => { :type => :attr, :name => "decoy", :default => "unknown" },
                  "interface" => { :type => :attr, :name => "interface" },
                  "node" => { :type => :list_class, :class => @@IDMEFNode },
                  "user" => { :type => :list_class, :class => @@IDMEFUser },
                  "process" => { :type => :list_class, :class => @@IDMEFProcess },
                  "service" => { :type => :list_class, :class => @@IDMEFService },
                  "file" => { :type => :list_class, :class => @@IDMEFFile }
                }
  
  # RFC 4765: Impact Class
  @@IDMEFImpact = { :type => :class,
                  :name => "Impact",
                  "severity" => { :type => :attr, :name => "severity" },
                  "completion" => { :type => :attr, :name => "completion" },
                  "type" => { :type => :attr, :name => "type", :default => "other" },
                }
  
  # RFC 4765: Action Class
  @@IDMEFAction = { :type => :class,
                  :name => "Action",
                  "category" => { :type => :attr, :name => "category", :default => "other" },
                  "description" => { :type => :value },
                }
  
  # RFC 4765: Confidence Class
  @@IDMEFConfidence = { :type => :class,
                      :name => "Confidence",
                      "rating" => { :type => :attr, :name => "rating", :default => "numeric" },
                      "confidence" => { :type => :value },
                    }
  
  # RFC 4765: Reference Class
  @@IDMEFReference = { :type => :class,
                     :name => "Reference",
                     "origin" => { :type => :attr, :name => "origin", :default => "unknown" },
                     "meaning" => { :type => :attr, :name => "meaning" },
                     "name" => { :type => :list_value, :name => "name" },
                     "url" => { :type => :list_value, :name => "url" }
                   }
  
  # RFC 4765: AdditionalData Class
  @@IDMEFAdditionalData = { :type => :class,
                          :name => "AdditionalData",
                          "meaning" => { :type => :attr, :name => "meaning" },
                          "type" => { :type => :attr, :name => "type" },
                          "data" => { :type => :list_value, :name => :type }
                        }
  # RFC 4765: CorrelationAlert Class
  @@IDMEFCorrelationAlert = { :type => :class,
                            :name => "CorrelationAlert",
                            "name" => { :type => :list_value, :name => "name" },
                            "alertident" => { :type => :list_value, :name => "alertident" }
                          }
  
  # RFC 4765: Assessment Class
  @@IDMEFAssessment = { :type => :class,
                      :name => "Assessment",
                      "impact" => { :type => :list_class, :class => @@IDMEFImpact },
                      "action" => { :type => :list_class, :class => @@IDMEFAction },
                      "confidence" => { :type => :list_class, :class => @@IDMEFConfidence }
                    }
  
  # RFC 4765: Classification Class
  @@IDMEFClassification = { :type => :class,
                          :name => "Classification",
                          "text" => { :type => :attr, :name => "text" },
                          "reference" => { :type => :list_class, :class => @@IDMEFReference }
                        }
  
  # RFC 4765: Alert Class
  @@IDMEFAlert = { :type => :class,
                 :name => "Alert",
                 "messageid" => { :type => :attr, :name => "messageid" },
                 "create_time" => { :type => :list_value, :name => "CreateTime", :format => :datetime},
                 "detect_time" => { :type => :list_value, :name => "DetectTime", :format => :datetime },
                 "analyzer_time" => { :type => :list_value, :name => "AnalyzerTime", :format => :datetime },
                 "analyzer" => { :type => :list_class, :class => @@IDMEFAnalyzer },
                 "classification" => { :type => :list_class, :class => @@IDMEFClassification },
                 "source" => { :type => :list_class, :class => @@IDMEFSource },
                 "target" => { :type => :list_class, :class => @@IDMEFTarget },
                 "assessment" => { :type => :list_class, :class => @@IDMEFAssessment },
                 "additional_data" => { :type => :list_class, :class => @@IDMEFAdditionalData },
                 "correlation_alert" => { :type => :list_class, :class => @@IDMEFCorrelationAlert },
               }
  
  # RFC 4765: Message Class
  @@IDMEFMessage = { :type => :class,
                   :name => "IDMEF-Message",
                   "alert" => { :type => :list_class, :class => @@IDMEFAlert },
                 }

  @@local_paths = {
    "alert.analyzer(0).name" => ["%{product}", "%{devname}"],
    "alert.analyzer(0).manufacturer" => ["%{vendor}"],
    "alert.create_time" => ["%{@timestamp}"],
    "alert.detect_time" => ["%{@timestamp}"],
    "alert.analyzer_time" => ["%{@timestamp}"],
    "alert.source(0).node.address(0).address" => ["%{srcip}", "%{src}"],
    "alert.source(0).node.name" => ["%{shost}", "%{srchost}", "%{shostname}", "%{srchostname}", "%{sname}", "%{srcname}"],
    "alert.source(0).service.port" => ["%{spt}", "%{sport}", "%{s_port}"],
    "alert.source(0).service.name" => ["%{sservice}", "%{srcservice}"],
    "alert.target(0).node.address(0).address" => ["%{hostip}", "%{dstip}", "%{dst}", "%{ip}"],
    "alert.target(0).node.name" => ["%{host}", "%{hostname}", "%{shost}", "%{srchost}", "%{shostname}", "%{srchostname}", "%{sname}", "%{srcname}"],
    "alert.target(0).service.port" => ["%{dpt}", "%{dport}", "%{d_port}"],
    "alert.target(0).service.name" => ["%{service}", "%{service_id}", "%{dservice}", "%{dstservice}"],
    "alert.target(0).user.user_id(0).name" => ["%{user}", "%{dstuser}", "%{duser}"],
    "alert.target(0).user.user_id(0).number" => ["%{uid}", "%{dstuid}", "%{duid}"],
    "alert.target(0).process.name" => ["%{proc}", "%{process}"],
    "alert.target(0).process.pid" => ["%{dpid}", "%{pid}"],
    "alert.classification.text" => ["%{rule_name}", "%{event}", "%{message}"],
    "alert.assessment.impact.severity" => ["%{severity}", "%{level}"],
    "alert.assessment.action.description" => ["%{action}"],
  }

  private
  def idmefpaths_to_xml(event, paths, doc = nil)
      # create the document if not existing
      if doc.nil?
          doc = Nokogiri::XML::Document.new
          if @validate_xml
            doc.create_external_subset('IDMEF-Message', nil, @dtd_path)
          end
          doc.root = Nokogiri::XML::Node.new('IDMEF-Message', doc)
          doc.root.add_namespace_definition('idmef', 'http://iana.org/idmef')
      end

      # translate all path inot the xml
      paths.each do |path, values|
          if !values.kind_of?(Array)
            values = [values]
          end

          formated_value = nil
          values.each do |value|
            formated_value = event.sprintf(value)
            # value is looking for non existing variable in event
            if /%{[^}]+}/.match(formated_value).nil?
                break
            end

            if formated_value == value
              formated_value = nil
            end
          end

          next if formated_value.nil? or formated_value.empty?

          @utf8_charset.convert(formated_value)

          xml_current_node = doc.root
          rfc_current_class = @@IDMEFMessage
          # path is an idmef path. example : alert.classification.text
          path.split('.').each do |idmefpath_name|
              # handle listed_path like alert.target(0).node.address(0).address
              listed_path = idmefpath_name.match(/^(.*)\((\d+)\)/)
              idmefpath_index = nil
              if listed_path
                 idmefpath_name = listed_path[1]
                 idmefpath_index = (listed_path ? listed_path[2] : 0).to_i
              end
  
              idmefpath_rfc_elm = rfc_current_class[idmefpath_name]

              idmef_node_name = nil
              if rfc_current_class[idmefpath_name][:type] == :list_class
                  idmef_node_name = idmefpath_rfc_elm[:class][:name]
              end
  
              # rfc class with multiple elements
              if !idmefpath_index.nil? && idmefpath_rfc_elm[:type] == :list_class
                 idmef_nodes = xml_current_node.xpath(idmef_node_name)

                 if idmef_nodes.empty?
                     idmef_node = Nokogiri::XML::Node.new(idmefpath_rfc_elm[:class][:name], doc)
                     xml_current_node << idmef_node

                 elsif idmef_nodes.length <= idmefpath_index
                     idmef_node = idmef_nodes[-1]
                     (idmef_nodes.length..idmefpath_index).each do |idx|
                         tmp_node = Nokogiri::XML::Node.new(idmefpath_rfc_elm[:class][:name], doc)
                         idmef_node.after(tmp_node)
                         idmef_node = tmp_node
                     end

                 elsif idmef_nodes.length > idmefpath_index
                     idmef_node = idmef_nodes[idmefpath_index]
                 end

                 xml_current_node = idmef_node
                 rfc_current_class = idmefpath_rfc_elm[:class]

              # rfc class with on element
              elsif idmefpath_index.nil? && idmefpath_rfc_elm[:type] == :list_class
                 idmef_node = xml_current_node.xpath(idmef_node_name).first
                 idmef_node = idmef_node || Nokogiri::XML::Node.new(idmefpath_rfc_elm[:class][:name], doc)
                 xml_current_node << idmef_node
                 xml_current_node = idmef_node
                 rfc_current_class = idmefpath_rfc_elm[:class]

              # rfc multiple values
              elsif idmefpath_rfc_elm[:type] == :list_value
                 if rfc_current_class[idmefpath_name][:name] == :type
                   node_name =  xml_current_node["type"]
                 else
                   node_name = rfc_current_class[idmefpath_name][:name]
                 end

                 idmef_node = Nokogiri::XML::Node.new(node_name, doc)

                 # reformat datetime with the expected format described in idmef rfc
                 if rfc_current_class[idmefpath_name][:format] == :datetime
                   alert_time = DateTime.parse(formated_value)
                   formated_value = alert_time.strftime(@@IDMEF_Time_Format)
                   seconds = alert_time.to_time.to_i + 2208988800
                   seconds_fraction = (alert_time.to_time.usec. / (1000000.0 / (2 ** 32))).to_i
                   idmef_node["ntpstamp"] = "0x%08x.0x%08x" % [seconds, seconds_fraction]
                 end

                 idmef_node.content = formated_value

                 xml_current_node << idmef_node

              # rfc attribute
              elsif idmefpath_rfc_elm[:type] == :attr
                 xml_current_node[rfc_current_class[idmefpath_name][:name]] = formated_value.to_s

              end

              # set default values as described in rfc
              rfc_current_class.each do |element, value|
                  # value is a ref, a string or a hash, we want hashs
                  next if !value.respond_to?(:each_pair)

                  if value[:default] && value[:type] == :attr && !xml_current_node[value[:name]]
                      xml_current_node[value[:name]] = value[:default]
                  end
              end
          end
      end
      return doc
  end

  private
  def xml_to_string(doc)
      # add namespace "idmef"
      doc.root.traverse do |node|
        if node.type != Nokogiri::XML::Node::TEXT_NODE
          node.name = 'idmef:' + node.name
        end
      end

      # return a oneline xml without spaces
      return doc.serialize(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML).sub("\n", "").strip
  end

  public
  def initialize(params={})
    super(params)
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger

    if @defaults
      @allpaths = @@local_paths.merge(@paths)
    else
      @allpaths = @paths
    end

    if @additionaldata
      # Find all event's keys already used in @@IDMEF paths values
      @allpaths_event_keys = []
      @allpaths.each do |key, values|
        if !values.kind_of?(Array)
          values = [values]
        end

        values.each do |value|
          match = value.match(/%{([^}]+)}/)
          if match
            @allpaths_event_keys += match.captures
          end
        end
      end
    end

    if @validate_xml
      @dtd_path = File.dirname(File.expand_path(__FILE__)) + "/idmef-message.dtd"
      @dtd_options = Nokogiri::XML::ParseOptions.new()
      @dtd_options.recover
      @dtd_options.dtdload
      @dtd_options.dtdvalid
    end
  end

  public
  def encode(event)
    # Set messageid and analyzerid
    paths = { "%s.messageid" % @type => java.util.UUID.randomUUID.to_s,
              "%s.analyzer(0).analyzerid" % @type => Socket.gethostname.to_s
            }

    # CreateTime is required in IDMEF RFC
    if !@allpaths.include? "alert.create_time"
      paths["alert.create_time"] = DateTime.now().strftime(@@IDMEF_Time_Format) 
    end

    # Classification is required in IDMEF RFC
    if !@allpaths.include? "alert.classification.text"
      paths["alert.classification.text"] = "Unknown alert"
    end

    xml = idmefpaths_to_xml(event, paths)
    
    # Set configured paths
    xml = idmefpaths_to_xml(event, @allpaths, xml)

    # Add unused event data to IDMEF additional data
    if @additionaldata
      additionaldata_idx = xml.xpath('/idmef-message/alert/addionnaldata').length

      event.to_hash.each do |key, value|
        next if value.to_s.empty? or @allpaths_event_keys.include? key

        if value.kind_of?(Integer)
          value_type = "integer"
        elsif value.kind_of?(Float)
          value_type = "real"
        else
          value_type = "string"
        end

        paths = { "alert.additional_data(%d).meaning" % additionaldata_idx => key,
                  "alert.additional_data(%d).type" % additionaldata_idx => value_type,
                  "alert.additional_data(%d).data" % additionaldata_idx => value.to_s,
                }

        xml = idmefpaths_to_xml(event, paths , xml)
        additionaldata_idx += 1
      end
    end

    if @validate_xml
      xml_dtd = Nokogiri::XML.parse(xml.to_xml, nil, nil, @dtd_options)
      if !xml_dtd.validate.nil? and !xml_dtd.validate.empty?
        raise "IDMEF XML generated is not valid. Errors: %s." % xml_dtd.validate.join(', ')
      end
      xml.external_subset.remove
    end  

    # Create the XML
    @on_event.call(event, xml_to_string(xml) + NL)
  end

end
