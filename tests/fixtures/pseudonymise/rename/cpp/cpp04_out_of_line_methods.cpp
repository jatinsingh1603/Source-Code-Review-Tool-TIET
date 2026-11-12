class SessionRegistry {
public:
    int register_token(int sessionToken);
    static int limit();

private:
    int issued_;
};

int SessionRegistry::register_token(int sessionToken) {
    issued_ += sessionToken;
    return issued_;
}

int SessionRegistry::limit() { return 64; }
