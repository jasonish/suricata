#[derive(Debug, Default)]
#[repr(C)]
pub struct Config {
    /// Allow success on a partially successful decode.
    pub allow_partial: bool,

    /// Ignore white space in the input data.
    pub ignore_whitespace: bool,
}

pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, ()> {
    decode_with_config(input, &Config::default())
}

/// Decode base64 from the provided input and config returning the output as
/// a Vec<u8>.
///
/// The config allows setting of options such as allowing partial decode and
/// ignoring whitespace.
///
/// TODO: Define errors.
pub fn decode_with_config<T: AsRef<[u8]>>(input: T, config: &Config) -> Result<Vec<u8>, ()> {
    let input = input.as_ref();
    let mut offset = 0;
    let mut output = vec![];
    let mut segment_output = [0, 0, 0, 0];
    loop {
        if input.len() - offset < 4 {
            break;
        }

        let mut trimmed_segment = [0, 0, 0, 0];

        let segment = if config.ignore_whitespace {
            let mut slen = 0;
            for c in &input[offset..] {
                if *c == b' ' {
                    offset += 1;
                    continue;
                } else {
                    trimmed_segment[slen] = *c;
                    slen += 1;
                    offset += 1;
                }
                if slen == 4 {
                    break;
                }
            }
            if slen < 4 {
                break;
            }
            &trimmed_segment
        } else {
            offset += 4;
            &input[offset - 4..offset]
        };

        // If we don't have at least 4 bytes, don't attempt to decode.
        if segment.len() < 4 {
            break;
        }

        if let Ok(n) = base64::decode_config_slice(segment, base64::STANDARD, &mut segment_output) {
            output.extend(&segment_output[0..n]);
        } else {
            if !config.allow_partial {
                // Error out as we hit a decoding error.
                return Err(());
            } else {
                break;
            }
        }
    }

    // Should we return an error if no output is decoded? This could happen if
    // partial decoding is allowed, but there was no valid data to decode.
    // Alternatively we can leave this up to the caller is it would have
    // explicitly asked for partial decode, so it could also check the length of
    // the data returned.
    Ok(output)
}

/// Decode base64 input into a pre-allocated slice.
/// 
/// To be used behind the C API as that would mostly likely take an output
/// buffer as an argument.
/// 
/// NOT TESTED, NEEDS CLEANUP.
pub fn decode_with_config_slice<T: AsRef<[u8]>>(
    input: T, config: &Config, xoutput: &mut [u8],
) -> Result<Vec<u8>, ()> {
    let input = input.as_ref();
    let mut offset = 0;
    let mut output = vec![];
    let mut segment_output = [0, 0, 0, 0];
    let mut xoutput_len = 0;
    loop {
        if input.len() - offset < 4 {
            break;
        }

        let mut trimmed_segment = [0, 0, 0, 0];

        let segment = if config.ignore_whitespace {
            let mut slen = 0;
            for c in &input[offset..] {
                if *c == b' ' {
                    offset += 1;
                    continue;
                } else {
                    trimmed_segment[slen] = *c;
                    slen += 1;
                    offset += 1;
                }
                if slen == 4 {
                    break;
                }
            }
            if slen < 4 {
                break;
            }
            &trimmed_segment
        } else {
            offset += 4;
            &input[offset - 4..offset]
        };

        // If we don't have at least 4 bytes, don't attempt to decode.
        if segment.len() < 4 {
            break;
        }

        if let Ok(n) = base64::decode_config_slice(segment, base64::STANDARD, &mut xoutput[xoutput_len..]) {
            //output.extend(&segment_output[0..n]);
            xoutput_len += n;
        } else {
            if !config.allow_partial {
                // Error out as we hit a decoding error.
                return Err(());
            } else {
                break;
            }
        }
    }

    // Should we return an error if no output is decoded? This could happen if
    // partial decoding is allowed, but there was no valid data to decode.
    // Alternatively we can leave this up to the caller is it would have
    // explicitly asked for partial decode, so it could also check the length of
    // the data returned.
    Ok(output)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_decode_complete_string() {
        let input = "SGVsbG8gV29ybGR6";
        let output = decode(input).unwrap();
        assert_eq!(&output, b"Hello Worldz");
    }

    #[test]
    fn test_decode_incomplete_string() {
        let input = "SGVsbG8gV29ybGR";
        let output = decode_with_config(input, &Config::default()).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "Hello Wor");
    }

    #[test]
    fn test_decode_complete_string_with_space() {
        let config = Config {
            ignore_whitespace: true,
            ..Default::default()
        };
        let input = "SGVs bG8 gV29y bGQ=";
        let output = decode_with_config(input, &config).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "Hello World");
    }
}
