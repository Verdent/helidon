package io.helidon.builder.processor.tools.model;

import java.io.IOException;
import java.io.Writer;

import static io.helidon.builder.processor.tools.model.ClassModel.PADDING_TOKEN;

class ModelWriter extends Writer {

    private final Writer delegate;
    private final String padding;
    private String currentPadding = ""; //no padding
    private int paddingLevel = 0;
    private boolean firstWrite = true;

    ModelWriter(Writer delegate, String padding) {
        this.delegate = delegate;
        this.padding = padding;
    }

    void increasePaddingLevel() {
        paddingLevel++;
        currentPadding = padding.repeat(paddingLevel);
    }

    void decreasePaddingLevel() {
        paddingLevel--;
        currentPadding = padding.repeat(paddingLevel);
    }

    @Override
    public void write(String str) throws IOException {
        if (firstWrite) {
            delegate.write(currentPadding);
            firstWrite = false;
        }
        String padded = str.replaceAll("\n", "\n" + currentPadding);
        padded = padded.replaceAll(PADDING_TOKEN, padding);
        delegate.write(padded);
    }

    @Override
    public void write(char[] cbuf, int off, int len) throws IOException {
        delegate.write(cbuf, off, len);
    }

    @Override
    public void flush() throws IOException {
        delegate.flush();
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}