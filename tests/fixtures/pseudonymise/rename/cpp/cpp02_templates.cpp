template <typename ValueType>
class RingBuffer {
public:
    explicit RingBuffer(int capacity) : capacity_(capacity), head_(0) {}

    ValueType peek(int offset) const { return slots_[(head_ + offset) % capacity_]; }

private:
    ValueType slots_[16];
    int capacity_;
    int head_;
};
