package io.helidon.json.processor;

class RollingArrayJsonParser extends AbstractJsonParser {

    private boolean finalBuffer;
    private byte[][] buffers;
    private int currentBufferIndex = 0;

    RollingArrayJsonParser(byte[][] buffers) {
        super(buffers[0]);
        this.buffers = buffers;
        this.finalBuffer = buffers.length == 1;
    }

    public void reset(byte[][] buffers) {
        this.buffers = buffers;
        this.currentBufferIndex = 0;
        this.finalBuffer = buffers.length == 1;
        reset(buffers[currentBufferIndex]);
    }

    @Override
    public boolean hasNext() {
        return !finalBuffer || super.hasNext();
    }

    @Override
    public byte readNextByte() {
        if (currentIndex + 1 == bufferLength) {
            if (finalBuffer) {
                throw new JsonException("Incomplete JSON data.");
            }
            readMoreData();
        }
        return super.readNextByte();
    }

    private void readMoreData() {
        this.buffer = buffers[++currentBufferIndex];
        this.finalBuffer = buffers.length == currentBufferIndex + 1;
    }

}
