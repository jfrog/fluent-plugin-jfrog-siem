# spec/data_normalization_spec.rb
#
# Tests for Xray#data_normalization covering JOBS-2850:
#   When violation properties lack cvss_v2 / cvss_v3 (e.g. Security violations
#   for issues with no CVSS score, or only a CVSS v4 score) the method must NOT
#   raise NoMethodError on `cvss[0..2]`.
#
# Expected results before the fix:
#   - Violations without CVSS v2/v3 data   → FAIL  (demonstrates the bug)
#   - CVSS score without a vector          → FAIL
#   - Missing impacted_artifacts           → FAIL
#   - Security-with-CVSS v2/v3 tests       → PASS  (existing logic is correct)

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
  # JOBS-2850: Security violation with a CVE but no CVSS data at all
  # ─────────────────────────────────────────────────────────────────────────
  describe 'Security violation with a CVE but without CVSS data' do
    let(:security_violation_no_cvss) do
      {
        'issue_id'           => 'SIEMTEST-NOCVSS-1',
        'type'               => 'Security',
        'properties'         => [{ 'cve' => 'CVE-2099-28500' }],
        'impacted_artifacts' => ['default/npm-siem-test/siem-mit-pkg/-/siem-mit-pkg-1.0.0.tgz']
      }
    end

    it 'does not raise an error (regression for JOBS-2850)' do
      expect { xray.data_normalization(security_violation_no_cvss) }.not_to raise_error
    end

    it 'still sets the cve' do
      result = xray.data_normalization(security_violation_no_cvss)
      expect(result['cve']).to eq('CVE-2099-28500')
    end

    it 'does not set cvss_score or cvss_version' do
      result = xray.data_normalization(security_violation_no_cvss)
      expect(result).not_to have_key('cvss_score')
      expect(result).not_to have_key('cvss_version')
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # JOBS-2850: Security violation with only a CVSS v4 score
  # ─────────────────────────────────────────────────────────────────────────
  describe 'Security violation with only CVSS v4 data' do
    let(:security_violation_v4) do
      {
        'issue_id'           => 'XRAY-1073490',
        'type'               => 'Security',
        'properties'         => [
          {
            'cve'     => 'CVE-2026-84445',
            'cwe'     => ['CWE-129', 'CWE-248'],
            'cvss_v4' => '8.7/CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'
          }
        ],
        'impacted_artifacts' => ['default/build-info/some-build']
      }
    end

    it 'does not raise an error (regression for JOBS-2850)' do
      expect { xray.data_normalization(security_violation_v4) }.not_to raise_error
    end

    it 'sets cvss_score from cvss_v4' do
      result = xray.data_normalization(security_violation_v4)
      expect(result['cvss_score']).to eq('8.7')
    end

    it 'sets cvss_version from cvss_v4' do
      result = xray.data_normalization(security_violation_v4)
      expect(result['cvss_version']).to eq('4.0')
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # Security violation with both CVSS v3 and v4 — v3 is kept
  # ─────────────────────────────────────────────────────────────────────────
  describe 'Security violation with both CVSS v3 and v4 (v3 kept)' do
    let(:security_violation_v3_v4) do
      {
        'issue_id'           => 'CVE-2024-5678',
        'type'               => 'Security',
        'properties'         => [
          {
            'cve'     => 'CVE-2024-5678',
            'cvss_v3' => '7.5/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            'cvss_v4' => '8.7/CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'
          }
        ],
        'impacted_artifacts' => ['default/maven-repo/some-lib/1.0/some-lib-1.0.jar']
      }
    end

    it 'uses cvss_v3, not cvss_v4' do
      result = xray.data_normalization(security_violation_v3_v4)
      expect(result['cvss_score']).to eq('7.5')
      expect(result['cvss_version']).to eq('3.1')
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # Security violation with a CVSS score but no vector (e.g. custom issues)
  # ─────────────────────────────────────────────────────────────────────────
  describe 'Security violation with a CVSS score but no vector' do
    let(:security_violation_score_only) do
      {
        'issue_id'           => 'CUSTOM-ISSUE-1',
        'type'               => 'Security',
        'properties'         => [{ 'cve' => 'CVE-2017-1000386', 'cvss_v2' => '2.4' }],
        'impacted_artifacts' => ['default/maven-repo/aero/aero/0.2.3/aero-0.2.3.jar']
      }
    end

    it 'does not raise an error' do
      expect { xray.data_normalization(security_violation_score_only) }.not_to raise_error
    end

    it 'sets cvss_score' do
      result = xray.data_normalization(security_violation_score_only)
      expect(result['cvss_score']).to eq('2.4')
    end

    it 'does not set cvss_version' do
      result = xray.data_normalization(security_violation_score_only)
      expect(result).not_to have_key('cvss_version')
    end
  end

  # ─────────────────────────────────────────────────────────────────────────
  # Violation without impacted_artifacts (key absent or null)
  # ─────────────────────────────────────────────────────────────────────────
  describe 'Violation without impacted_artifacts' do
    it 'does not raise an error when the key is absent' do
      violation = { 'issue_id' => 'CVE-2099-28500', 'type' => 'Security', 'properties' => [{ 'cve' => 'CVE-2099-28500' }] }
      expect { xray.data_normalization(violation) }.not_to raise_error
    end

    it 'sets an empty impacted_artifacts_url when the value is null' do
      violation = { 'issue_id' => 'CVE-2099-28500', 'type' => 'Security', 'impacted_artifacts' => nil }
      result = xray.data_normalization(violation)
      expect(result['impacted_artifacts_url']).to eq([])
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
