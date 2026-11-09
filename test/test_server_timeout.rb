require 'helper'
require 'socket'
require 'openssl'
require 'logger'

# Server#login! logs through Rails.logger; give it a silent one outside Rails.
unless defined?(Rails)
  module Rails
    def self.logger
      @logger ||= Logger.new(nil)
    end
  end
end

# Exercises the :timeout option against a real TLS socket rather than stubs: the
# point is how blocking reads behave when the registry stops answering.
class TestEppServerTimeout < Test::Unit::TestCase
  EPP_NS = 'urn:ietf:params:xml:ns:epp-1.0'.freeze

  def self.result_frame(code)
    %(<?xml version="1.0" encoding="UTF-8"?><epp xmlns="#{EPP_NS}"><response>) +
      %(<result code="#{code}"><msg>ok</msg></result><trID><svTRID>sv</svTRID></trID></response></epp>)
  end

  GREETING = %(<?xml version="1.0" encoding="UTF-8"?><epp xmlns="#{EPP_NS}"><greeting><svID>test</svID></greeting></epp>).freeze

  # A TLS server that answers greeting/login/command/logout in order, and goes
  # silent from the step named in stall_at. Records the commands it received.
  class FakeRegistry
    attr_reader :port, :received

    def initialize(stall_at:)
      @stall_at = stall_at
      @received = []
      key  = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=registry.test')
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after  = Time.now + 3600
      cert.sign(key, OpenSSL::Digest.new('SHA256'))
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert = cert
      ctx.key = key
      @tcp  = TCPServer.new('127.0.0.1', 0)
      @port = @tcp.addr[1]
      ssl_server = OpenSSL::SSL::SSLServer.new(@tcp, ctx)
      @thread = Thread.new { serve(ssl_server.accept) }
    end

    def close
      @thread.kill
      @tcp.close
    end

    private

    def serve(sock)
      return hang if @stall_at == :greeting
      write_frame(sock, GREETING)

      { login: 1000, command: 1000, logout: 1500 }.each do |step, code|
        frame = read_frame(sock) or return
        @received << step
        return hang if @stall_at == step
        write_frame(sock, TestEppServerTimeout.result_frame(code))
      end
      hang
    rescue IOError, SystemCallError, OpenSSL::SSL::SSLError
      nil
    end

    def hang
      sleep 30
    end

    def write_frame(sock, xml)
      sock.write([xml.bytesize + 4].pack('N') + xml)
    end

    def read_frame(sock)
      header = sock.read(4) or return
      sock.read(header.unpack('N')[0] - 4)
    end
  end

  def run_command(registry, timeout:)
    server = EPP::Server.new('TEST', 'secret', '127.0.0.1', port: registry.port, timeout: timeout)
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    error = nil
    begin
      server.connection { server.with_login { server.request(EPP::Commands::Check.new(EPP::Domain::Check.new('example.ph'))) } }
    rescue Exception => e # rubocop:disable Lint/RescueException
      error = e
    end
    [error, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started]
  end

  def teardown
    @registry&.close
  end

  def test_completes_a_full_session_within_the_deadline
    @registry = FakeRegistry.new(stall_at: nil)
    error, = run_command(@registry, timeout: 5)

    assert_nil error
    assert_equal %i[login command logout], @registry.received
  end

  def test_raises_io_timeout_when_the_registry_never_sends_its_greeting
    @registry = FakeRegistry.new(stall_at: :greeting)
    error, elapsed = run_command(@registry, timeout: 0.5)

    assert_kind_of IO::TimeoutError, error
    assert_operator elapsed, :<, 1.5
  end

  def test_raises_io_timeout_and_skips_logout_when_the_command_reply_never_comes
    @registry = FakeRegistry.new(stall_at: :command)
    error, elapsed = run_command(@registry, timeout: 0.5)

    assert_kind_of IO::TimeoutError, error
    assert_operator elapsed, :<, 1.5
    # Logging out would read the late command reply as the logout reply.
    assert_equal %i[login command], @registry.received
  end

  def test_the_deadline_covers_the_whole_session_not_each_read
    @registry = FakeRegistry.new(stall_at: :logout)
    error, elapsed = run_command(@registry, timeout: 0.5)

    assert_kind_of IO::TimeoutError, error
    assert_operator elapsed, :<, 1.5
  end
end
