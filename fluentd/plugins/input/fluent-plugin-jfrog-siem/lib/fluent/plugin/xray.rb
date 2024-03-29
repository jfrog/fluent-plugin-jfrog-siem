require 'concurrent'
require 'concurrent-edge'
require 'json'
require "fluent/plugin/position_file"

class Xray
  def initialize(jpd_url, username, api_key, token, wait_interval, batch_size, pos_file_path, router, tag)
    @jpd_url = jpd_url
    @username = username
    @api_key = api_key
    @token = token
    @wait_interval = wait_interval
    @batch_size = batch_size
    @pos_file_path = pos_file_path
    @router = router
    @tag = tag
  end

  def violations(date_since)
    violations_channel = Concurrent::Channel.new(capacity: @batch_size)
    page_number = 1
    timer_task = Concurrent::TimerTask.new(execution_interval: @wait_interval, timeout_interval: 30) do
      xray_json = {"filters": { "created_from": date_since }, "pagination": {"order_by": "created","limit": @batch_size ,"offset": page_number } }
      puts "Fetching Xray Violations with #{xray_json} parameters"
      resp = get_violations(xray_json)
      page_violation_count = resp['violations'].length
      puts "Total violations count is #{resp['total_violations']}"
      if resp['total_violations'] > 0
        puts "Number of Violations in page #{page_number} are #{page_violation_count}"
        resp['violations'].each {|v| violations_channel = process(v, violations_channel) }
        page_number += 1 if next_page?(page_violation_count)
      end
    end
    timer_task.execute

    violations_channel
  end

  def violation_details(violations_channel)
    violations_channel.each do |v|
      Concurrent::Promises.future(v) do |v|
        process_violation_details(v['violation_details_url'])
        pos_file = PositionFile.new(@pos_file_path)
        puts "Adding issue #{v['issue_id']} to position file at #{@pos_file_path}"
        pos_file.write(v)
      end
    end
  end

  def process_violation_details(xray_violation_detail_url)
    begin
      detailResp_json = data_normalization(get_violations_detail(xray_violation_detail_url))
      time = Fluent::Engine.now
      puts "Emitting normalized Xray Violation #{detailResp_json['issue_id']}"
      @router.emit(@tag, time, detailResp_json)
    rescue => e
      puts "Process Violation details error: #{e}"
      raise Fluent::ConfigError, "Process Violation details error: #{e}"
    end
  end

  def get_violations_detail(xray_violation_detail_url)
    if !@token.nil? && @token != ''
      response = RestClient::Request.new(
          :method => :get,
          :url => @jpd_url + xray_violation_detail_url[xray_violation_detail_url.index('/xray/'),xray_violation_detail_url.length],
          :headers => { :accept => :json, :content_type => :json, Authorization:'Bearer ' + @token }
      )
    elsif !@api_key.nil? && @api_key != ''
      response = RestClient::Request.new(
          :method => :get,
          :url => @jpd_url + xray_violation_detail_url[xray_violation_detail_url.index('/xray/'),xray_violation_detail_url.length],
          :user => @username,
          :password => @api_key
      )
    end

    response.execute do |response, request, result|
      case response.code
      when 200
        return JSON.parse(response.to_s)
      else
        puts "Validation failed error (cannot reach Artifactory to pull Xray Violation details): #{response.to_json}"
        raise Fluent::ConfigError, "Validation failed error (cannot reach Artifactory to pull Xray Violation details): #{response.to_json}"
      end
    end
  end

  def data_normalization(detailResp_json)
    cve = []
    cvss_v2_list = []
    cvss_v3_list = []
    policy_list = []
    rule_list = []
    impacted_artifact_url_list = []
    if detailResp_json.key?('properties')
      properties = detailResp_json['properties']
      for index in 0..properties.length-1 do
        if properties[index].key?('cve')
          cve.push(properties[index]['cve'])
        end
        if properties[index].key?('cvss_v2')
          cvss_v2_list.push(properties[index]['cvss_v2'])
        end
        if properties[index].key?('cvss_v3')
          cvss_v3_list.push(properties[index]['cvss_v3'])
        end
      end

      detailResp_json["cve"] = cve.sort.reverse[0]
      cvss_v2 = cvss_v2_list.sort.reverse[0]
      cvss_v3 = cvss_v3_list.sort.reverse[0]
      if !cvss_v3.nil?
        cvss = cvss_v3
      elsif !cvss_v2.nil?
        cvss = cvss_v2
      end
      cvss_score = cvss[0..2]
      cvss_version = cvss.split(':')[1][0..2]
      detailResp_json["cvss_score"] = cvss_score
      detailResp_json["cvss_version"] = cvss_version
    end

    if detailResp_json.key?('matched_policies')
      matched_policies = detailResp_json['matched_policies']
      for index in 0..matched_policies.length-1 do
        if matched_policies[index].key?('policy')
          policy_list.push(matched_policies[index]['policy'])
        end
        if matched_policies[index].key?('rule')
          rule_list.push(matched_policies[index]['rule'])
        end
      end
      detailResp_json['policies'] = policy_list
      detailResp_json['rules'] = rule_list
    end

    detailResp_json['impacted_artifacts'].each do |impacted_artifact|
      matchdata = impacted_artifact.match /default\/(?<repo_name>[^\/]*)\/(?<path>.*)/
      if matchdata
        impacted_artifact_url = matchdata['repo_name'] + ":" + matchdata['path'] + " "
        impacted_artifact_url_list.append(impacted_artifact_url)
      else
        impacted_artifact_url_list.append(impacted_artifact)
      end
    end
    detailResp_json['impacted_artifacts_url'] = impacted_artifact_url_list
    return detailResp_json
  end

  def process(violation, violations_channel)
    pos_file = PositionFile.new(@pos_file_path)
    unless pos_file.processed?(violation)
      violations_channel << violation
    else
      puts "Violation #{violation['issue_id']} is already processed"
    end
    #violations_channel << violation unless pos_file.processed?(violation)
    violations_channel
  end

  private
  def get_violations(xray_json)
    if !@token.nil? && @token != ''
      puts "Validating JPD access token and fetching violations"
      response = RestClient::Request.new(
          :method => :post,
          :url => @jpd_url + "/xray/api/v1/violations",
          :payload => xray_json.to_json,
          :headers => { :accept => :json, :content_type => :json, Authorization:'Bearer ' + @token }
      )
    elsif !@api_key.nil? && @api_key != ''
      puts "Validating JPD API Key and fetching violations"
      response = RestClient::Request.new(
          :method => :post,
          :url => @jpd_url + "/xray/api/v1/violations",
          :payload => xray_json.to_json,
          :user => @username,
          :password => @api_key,
          :headers => { :accept => :json, :content_type => :json }
      )
    end
    response.execute do |response, request, result|
      case response.code
      when 200
        return JSON.parse(response.to_str)
      else
        puts "Validation failed error (cannot reach Artifactory to pull Xray Violations): #{response.to_json}"
        raise Fluent::ConfigError, "Validation failed error (cannot reach Artifactory to pull Xray Violations): #{response.to_json}"
      end
    end
  end

  def next_page?(count)
    count == @batch_size
  end

end

