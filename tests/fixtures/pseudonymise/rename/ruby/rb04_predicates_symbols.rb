class SessionRegistry
  attr_accessor :active_sessions

  def initialize
    @active_sessions = {}
  end

  def register(session_token, expiry)
    @active_sessions[:latest_token] = session_token
    @active_sessions[session_token] = expiry
  end

  def expired?(session_token, now)
    @active_sessions.fetch(session_token, 0) < now
  end

  def purge!(now)
    @active_sessions.reject! { |_token, expiry| expiry < now }
  end
end
