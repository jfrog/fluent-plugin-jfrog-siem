# spec/data_normalization_spec.rb
#
# Tests for Xray#data_normalization covering JOBS-2850:
#   When violation properties lack cvss_v2 / cvss_v3 (License or Operational
#   Risk violations) the method must NOT raise NoMethodError on `cvss[0..2]`.
#
# Expected results before the fix:
#   - License / Operational-Risk tests → FAIL  (demonstrates the bug)
#   - Security-with-CVSS tests          → PASS  (existing logic is correct)

[
  File.join(File.dirname(__FILE__), '..'),
  File.join(File.dirname(__FILE__), '..', 'lib/fluent/plugin'),
  File.join(File.dirname(__FILE__), '..', 'spec'),
].each do |dir|
  $LOAD_PATH.unshift(dir) unless $LOAD_PATH.include?(dir)
end

require 'spec_helper'

RSpec.describe Xray, '#data_normalization' do
  # Build an Xray instance with all dummy/nil params — we only need the method.
  # Constructor signature: (jpd_url, username, api_key, token, wait_interval,
  #                         batch_size, pos_file_path, router, tag)
  subject(:xray) do
    Xray.new(nil, nil, nil, nil, nil, nil, nil, nil, nil)
  end

  # ─────────────────────────────────────────────────────────────────────────
  # JOBS-2850: License violation — properties have no cvss_v2 / cvss_v3
  # ─────────────────────────────────────────────────────────────────────────
  describe 'License violation without CVSS data' do
    let(:license_violation) do
      {
        'issue_id'           => 'Apache-2.0',
        'type'               => 'License',
        'properties'         => [{ 'license' => 'Apache-2.0' }],
        'impacted_artifacts' => ['default/maven-repo-1/com/example/foo/bar.jar']
      }
    end

    it 'does not raise an error (regression for JOBS-2850)' do
      # BUG: cvss is nil → cvss[0..2] raises NoMethodError undefined method '[]' for nil
      expect { xray.data_normalization(license_violation) }.not_to raise_error
    end

    it 'returns a Hash' do
      result = xray.data_normalization(license_violation)
      expect(result).to be_a(Hash)
    end

    it 'does not set cvss_score when CVSS data is absent' do
      result = xray.data_normalization(license_violation)
      expect(result).not_to have_key('cvss_score')
    end

    it 'does not set cvss_version when CVSS data is absent' do
      result = xray.data_normalization(license_violation)
      expect(result).not_to have_key('cvss_version')
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # JOBS-2850: Operational Risk violation — properties have no cvss_v2 / cvss_v3
  # ─────────────────────────────────────────────────────────────────────────
  describe 'Operational Risk violation without CVSS data' do
    let(:op_risk_violation) do
      {
        'issue_id'           => 'EOL-component-1234',
        'type'               => 'Operational Risk',
        'properties'         => [{ 'end_of_life' => 'true' }],
        'impacted_artifacts' => ['default/npm-repo/lodash/-/lodash-4.0.0.tgz']
      }
    end

    it 'does not raise an error (regression for JOBS-2850)' do
      # BUG: same as License — cvss stays nil, cvss[0..2] crashes
      expect { xray.data_normalization(op_risk_violation) }.not_to raise_error
    end

    it 'returns a Hash' do
      result = xray.data_normalization(op_risk_violation)
      expect(result).to be_a(Hash)
    end

    it 'does not set cvss_score when CVSS data is absent' do
      result = xray.data_normalization(op_risk_violation)
      expect(result).not_to have_key('cvss_score')
    end

    it 'does not set cvss_version when CVSS data is absent' do
      result = xray.data_normalization(op_risk_violation)
      expect(result).not_to have_key('cvss_version')
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # Security violation WITH CVSS v3 only (existing behaviour must keep working)
  # ─────────────────────────────────────────────────────────────────────────
  describe 'Security violation with CVSS v3 data' do
    let(:security_violation_v3) do
      {
        'issue_id'           => 'CVE-2021-44228',
        'type'               => 'Security',
        'properties'         => [
          {
            'cve'     => 'CVE-2021-44228',
            'cvss_v3' => '9.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
          }
        ],
        'impacted_artifacts' => ['default/maven-repo/log4j/core/2.14.1/log4j-core-2.14.1.jar']
      }
    end

    it 'does not raise an error' do
      expect { xray.data_normalization(security_violation_v3) }.not_to raise_error
    end

    it 'sets cvss_score to the leading numeric score (e.g. "9.8")' do
      result = xray.data_normalization(security_violation_v3)
      expect(result['cvss_score']).to eq('9.8')
    end

    it 'sets cvss_version to the CVSS major.minor version (e.g. "3.1")' do
      result = xray.data_normalization(security_violation_v3)
      expect(result['cvss_version']).to eq('3.1')
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # Security violation WITH both CVSS v2 AND v3 — v3 must be preferred
  # ─────────────────────────────────────────────────────────────────────────
  describe 'Security violation with both CVSS v2 and v3 (v3 preferred)' do
    let(:security_violation_both) do
      {
        'issue_id'           => 'CVE-2020-1234',
        'type'               => 'Security',
        'properties'         => [
          {
            'cve'     => 'CVE-2020-1234',
            'cvss_v2' => '7.5/AV:N/AC:L/Au:N/C:P/I:P/A:P',
            'cvss_v3' => '9.8/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
          }
        ],
        'impacted_artifacts' => ['default/maven-repo/some-lib/1.0/some-lib-1.0.jar']
      }
    end

    it 'does not raise an error' do
      expect { xray.data_normalization(security_violation_both) }.not_to raise_error
    end

    it 'uses cvss_v3 score (not cvss_v2) when both are present' do
      result = xray.data_normalization(security_violation_both)
      # v3 score is 9.8; v2 score is 7.5 — the result must reflect v3
      expect(result['cvss_score']).to eq('9.8')
    end

    it 'sets cvss_version from cvss_v3 when both are present' do
      result = xray.data_normalization(security_violation_both)
      expect(result['cvss_version']).to eq('3.1')
    end
  end
end
