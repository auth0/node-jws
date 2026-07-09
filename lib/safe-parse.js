function isObject(thing) {
  return Object.prototype.toString.call(thing) === "[object Object]";
}

function safeJsonParse(thing) {
  if (isObject(thing)) return thing;
  try {
    return JSON.parse(thing);
  } catch (e) {
    return undefined;
  }
}

// Custom JSON parser that preserves big integer precision
function safeJsonParseWithBigInt(text) {
  // Use regex to match big integers (including negative numbers) and convert them to strings
  var processedText = text.replace(
    /:(\s*)(-?\d{16,})/g,
    function (match, space, number) {
      // If the number exceeds the safe integer range, convert it to a string
      if (
        parseInt(number) > Number.MAX_SAFE_INTEGER ||
        parseInt(number) < Number.MIN_SAFE_INTEGER
      ) {
        return ":" + space + '"' + number + '"';
      }
      return match;
    }
  );

  try {
    return JSON.parse(processedText);
  } catch (e) {
    // If the processed text fails to parse, try the original text
    return JSON.parse(text);
  }
}

exports.safeJsonParse = safeJsonParse;
exports.safeJsonParseWithBigInt = safeJsonParseWithBigInt;
