package com.slytechs.jnet.jnetruntime.bpf.compiler.core;

/**
 * Represents compiler settings and options.
 */
public class CompilerOptions {

    private int optimizationLevel;
    private boolean debug;

    /**
     * Gets the optimization level.
     *
     * @return the optimization level
     */
    public int getOptimizationLevel() {
        return optimizationLevel;
    }

    /**
     * Sets the optimization level.
     *
     * @param optimizationLevel the optimization level to set
     */
    public void setOptimizationLevel(int optimizationLevel) {
        this.optimizationLevel = optimizationLevel;
    }

    /**
     * Checks if debug mode is enabled.
     *
     * @return true if debug mode is enabled, false otherwise
     */
    public boolean isDebug() {
        return debug;
    }

    /**
     * Enables or disables debug mode.
     *
     * @param debug true to enable debug mode, false to disable
     */
    public void setDebug(boolean debug) {
        this.debug = debug;
    }
}
