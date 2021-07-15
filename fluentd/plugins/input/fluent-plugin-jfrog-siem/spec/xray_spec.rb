[
  File.join(File.dirname(__FILE__), '..'),
  File.join(File.dirname(__FILE__), '..', 'lib/fluent/plugin'),
  File.join(File.dirname(__FILE__), '..', 'spec'),
].each do |dir|
  $LOAD_PATH.unshift(dir) unless $LOAD_PATH.include?(dir)
end

require 'xray'
require 'date'
require 'rspec'


RSpec.describe Xray do
  describe "#violation_details" do
    it "creates a future for every violation" do
      xray = Xray.new(@jpd_url, @username, @apikey, @wait_interval, @batch_size, @pos_file)
      violations = Concurrent::Array.new
      
      (1..5).each do |i|
        violations << i
      end
      
      promises = class_double("Concurrent::Promises").as_stubbed_const(:transfer_nested_constants => true)
      expect(promises).to receive(:future).exactly(5).times

      xray.violation_details(violations)
    end

    xit "updates pos file for every violation" do
      pos_file = double('pos_file')

      xray = Xray.new(@jpd_url, @username, @apikey, @wait_interval, @batch_size, "pos_file.txt")
      violations = Concurrent::Array.new
      
      (1..5).each do |i|
        violations << i
      end
      
      datetime = double (DateTime)
      expect(datetime).to receive(:parse)
      promises = class_double("Concurrent::Promises").as_stubbed_const(:transfer_nested_constants => true)
      allow(promises).to receive(:future) { |&block| block.call }

      expect(File).to receive(:open).with("pos_file.txt", "a").and_yield(pos_file)
      expect(pos_file).to receive(:puts).exactly(5).times

      xray.violation_details(violations)
    end
  end

  describe "#processed?" do
    
    let(:violation){ { "created": Date.parse(Date.today.to_s).strftime("%Y-%m-%dT%H:%M:%SZ"), "watch_name": "watch1", "issue_id": "55444"} }

    it "returns false when a violation has not been processed" do
      xray = Xray.new(@jpd_url, @username, @apikey, @wait_interval, @batch_size, @pos_file)
      
      allow(File).to receive(:open).and_yield []

      expect(xray.processed?(JSON.parse(violation.to_json))).to be_falsey
    end

    it "returns true when a violation was found in the pos file" do
      xray = Xray.new(@jpd_url, @username, @apikey, @wait_interval, @batch_size, @pos_file)
      
      matching_violation = [violation[:created], violation[:watch_name], violation[:issue_id]].join(',')
      another_violation = [violation[:created], "watch2", "12345"].join(',')
      allow(File).to receive(:open).and_yield [matching_violation, another_violation]

      expect(xray.processed?(JSON.parse(violation.to_json))).to be_truthy
    end

  end

end