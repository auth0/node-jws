'use strict';

var Buffer = require('safe-buffer').Buffer;

module.exports = function toBuffer(val, encoding) {
	if (Buffer.isBuffer(val)) {
		return val;
	}
	if (typeof val === 'string') {
		return Buffer.from(val, encoding || 'utf8');
	}
	if (typeof val === 'number') {
		// This won't work for very large or very small numbers, but is consistent
		// with previous behaviour at least
		val = val.toString();
		return Buffer.from(val, 'utf8');
	}
	return Buffer.from(JSON.stringify(val), 'utf8');
};
