require 'helper'
require 'logger'
require 'stringio'

class TestEppServerLogin < Test::Unit::TestCase
  # The login frame carries the registrar password, so it must never be logged.
  def test_login_does_not_log_the_request
    io = StringIO.new
    logger = Logger.new(io)
    stub_rails_logger(logger)

    server = EPP::Server.new('TEST', 'super-secret-pw', 'epp.test.host')
    response = stub(code: 1000)
    server.stubs(:send_recv_frame).returns(response)

    assert server.send(:login!)
    assert_not_match(/super-secret-pw/, io.string)
  end

  private

  # Before the fix, login! wrote through Rails.logger; give it one to write to.
  def stub_rails_logger(logger)
    Object.const_set(:Rails, Module.new) unless defined?(::Rails)
    ::Rails.stubs(:logger).returns(logger)
  end
end
