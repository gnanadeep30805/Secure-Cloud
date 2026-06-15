/**
 * services/eventBus.js
 * Typed SecurityEventBus — central nervous system for security events.
 * Consumers (anomalyDetector) register listeners; producers emit typed events.
 */
const { EventEmitter } = require("events");

class SecurityEventBus extends EventEmitter {
    constructor() {
        super();
        this.setMaxListeners(20);
    }

    authSuccess(data)   { this.emit("auth.success",   { ...data, ts: Date.now() }); }
    authFailure(data)   { this.emit("auth.failure",   { ...data, ts: Date.now() }); }
    totpFailure(data)   { this.emit("totp.failure",   { ...data, ts: Date.now() }); }
    fileUpload(data)    { this.emit("file.upload",    { ...data, ts: Date.now() }); }
    fileDownload(data)  { this.emit("file.download",  { ...data, ts: Date.now() }); }
    accessDenied(data)  { this.emit("access.denied",  { ...data, ts: Date.now() }); }
    externalProbe(data) { this.emit("external.probe", { ...data, ts: Date.now() }); }
    rateLimitHit(data)  { this.emit("rate.limit",     { ...data, ts: Date.now() }); }
    riskScored(data)    { this.emit("risk.scored",    { ...data, ts: Date.now() }); }
}

module.exports = new SecurityEventBus();
