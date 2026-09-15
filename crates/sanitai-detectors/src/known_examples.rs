//! Values that vendors and standards bodies publish *as* examples.
//!
//! They pass every format check by construction — Stripe's test cards are
//! Luhn-valid, the ISO IBAN samples pass mod-97, AWS's `AKIAIOSFODNN7EXAMPLE`
//! is a well-formed access key id — yet they are secret to nobody. Any
//! developer transcript that touches payments, banking or cloud SDKs is full
//! of them, and a scanner that reports `4242 4242 4242 4242` as a leaked card
//! teaches its user to ignore the report.
//!
//! Matching is exact on the matched text (after removing spaces/dashes for
//! numeric values) plus a few structural tells that only test data has.
//! Everything here is public documentation; nothing is a real credential.

/// PCI test PANs from processor documentation (Stripe, Braintree/PayPal,
/// Adyen, Authorize.net, Worldpay, the classic `4111…`). Stored without
/// separators.
const TEST_CARDS: &[&str] = &[
    // Stripe basic test cards.
    "4242424242424242",
    "4000056655665556",
    "5555555555554444",
    "2223003122003222",
    "5200828282828210",
    "5105105105105100",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
    "3056930009020004",
    "36227206271667",
    "3566002020360505",
    "6200000000000005",
    "6200000000000047",
    "6205500000000000004",
    // Stripe international / 3DS / decline test cards (4000 00… family is
    // handled by the prefix rule below; these are the non-4000 ones).
    "4000058260000005",
    "4000000760000002",
    "4000001240000000",
    "4000004840008001",
    "4000002500003155",
    "4000003800000446",
    "4000008260000000",
    "4000000000003220",
    "4000000000003063",
    "4000008400001629",
    "4000008400001280",
    "4000000000003055",
    "4000000000003097",
    "4000000000003238",
    "4000000000000077",
    "4000000000000093",
    "4000000000000101",
    "4000000000000119",
    "4000000000000259",
    "4000000000000267",
    "4000000000000275",
    "4000000000000283",
    "4000000000000291",
    "4000000000000309",
    "4000000000000317",
    "4000000000000325",
    "4000000000000333",
    "4000000000000341",
    "4000000000000358",
    "4000000000000366",
    "4000000000000374",
    "4000000000000382",
    "4000000000000390",
    "4000000000000408",
    "4000000000000416",
    "4000000000000424",
    "4000000000000432",
    "4000000000000440",
    "4000000000000457",
    "4000000000000465",
    "4000000000000473",
    "4000000000000481",
    "4000000000000499",
    "4000000000000507",
    "4000000000000515",
    "4000000000000523",
    "4000000000000531",
    "4000000000000549",
    "4000000000000556",
    "4000000000000564",
    "4000000000000572",
    "4000000000000580",
    "4000000000000598",
    "4000000000000606",
    "4000000000000614",
    "4000000000000622",
    "4000000000000630",
    "4000000000000648",
    "4000000000000655",
    "4000000000000663",
    "4000000000000671",
    "4000000000000689",
    "4000000000000697",
    "4000000000000705",
    "4000000000000713",
    "4000000000000721",
    "4000000000000739",
    "4000000000000747",
    "4000000000000754",
    "4000000000000762",
    "4000000000000770",
    "4000000000000788",
    "4000000000000796",
    "4000000000000804",
    "4000000000000812",
    "4000000000000820",
    "4000000000000838",
    "4000000000000846",
    "4000000000000853",
    "4000000000000861",
    "4000000000000879",
    "4000000000000887",
    "4000000000000895",
    "4000000000000903",
    "4000000000000911",
    "4000000000000929",
    "4000000000000937",
    "4000000000000945",
    "4000000000000952",
    "4000000000000960",
    "4000000000000978",
    "4000000000000986",
    "4000000000000994",
    "4000000000009995",
    "4000000000009987",
    "4000000000009979",
    "4000000000000002",
    "4000000000000010",
    "4000000000000028",
    "4000000000000036",
    "4000000000000044",
    "4000000000000069",
    "4000000000000127",
    "4000000000000135",
    "4000000000000143",
    "4000000000000150",
    "4000000000000168",
    "4000000000000176",
    "4000000000000184",
    "4000000000000192",
    "4000000000000200",
    "4000000000000218",
    "4000000000000226",
    "4000000000000234",
    "4000000000000242",
    // Braintree / PayPal sandbox, Authorize.net, Worldpay, Adyen, generic.
    "4111111111111111",
    "4012888888881881",
    "4222222222222",
    "4444333322221111",
    "4917610000000000",
    "4462030000000000",
    "4484070000000000",
    "4007000000027",
    "4012000033330026",
    "4012000077777777",
    "4012888818888",
    "4217651111111119",
    "4500600000000061",
    "5424000000000015",
    "5555555555554444",
    "5105105105105100",
    "2221000000000009",
    "2223000048400011",
    "2223016768739313",
    "2720999999999996",
    "6011000000000012",
    "6011000400000000",
    "371449635398431",
    "378734493671000",
    "343434343434343",
    "370000000000002",
    "30569309025904",
    "38520000023237",
    "3530111333300000",
    "3566111111111113",
    "6304000000000000",
    "6759649826438453",
    "6799990100000000019",
];

/// SWIFT IBAN Registry / ISO 13616 sample IBANs (one per country) plus the
/// handful that every tutorial reuses.
const TEST_IBANS: &[&str] = &[
    "GB82WEST12345698765432",
    "GB33BUKB20201555555555",
    "GB94BARC10201530093459",
    "GB29NWBK60161331926819",
    "DE89370400440532013000",
    "DE75512108001245126199",
    "DE02120300000000202051",
    "FR1420041010050500013M02606",
    "FR7630006000011234567890189",
    "NL91ABNA0417164300",
    "NL02ABNA0123456789",
    "BE68539007547034",
    "BE71096123456769",
    "CH9300762011623852957",
    "CH5604835012345678009",
    "ES9121000418450200051332",
    "ES7921000813610123456789",
    "IT60X0542811101000000123456",
    "IT40S0542811101000000123456",
    "AT611904300234573201",
    "AT483200000012345864",
    "IE29AIBK93115212345678",
    "SE4550000000058398257466",
    "SE7280000810340009783242",
    "DK5000400440116243",
    "DK9520000123456789",
    "NO9386011117947",
    "NO8330001234567",
    "FI2112345600000785",
    "FI1410093000123458",
    "PL61109010140000071219812874",
    "PL10105000997603123456789123",
    "PT50000201231234567890154",
    "PT50002700000001234567833",
    "LU280019400644750000",
    "LU120010001234567891",
    "GR1601101250000000012300695",
    "GR9608100010000001234567890",
    "HU42117730161111101800000000",
    "HU93116000060000000012345676",
    "CZ6508000000192000145399",
    "CZ5508000000001234567899",
    "RO49AAAA1B31007593840000",
    "RO66BACX0000001234567890",
    "BG80BNBG96611020345678",
    "BG18RZBB91550123456789",
    "HR1210010051863000160",
    "HR1723600001101234565",
    "LT121000011101001000",
    "LT601010012345678901",
    "LV80BANK0000435195001",
    "LV97HABA0012345678910",
    "EE382200221020145685",
    "EE471000001020145685",
    "MT84MALT011000012345MTLCAST001S",
    "MT31MALT01100000000000000000123",
    "CY17002001280000001200527600",
    "CY21002001950000357001234567",
    "SK3112000000198742637541",
    "SK8975000000000012345671",
    "SI56263300012039086",
    "SI56192001234567892",
    "IS140159260076545510730339",
    "LI21088100002324013AA",
    "LI7408806123456789012",
    "MC5811222000010123456789030",
    "MC5810096180790123456789085",
    "SM86U0322509800000000270100",
    "SM76P0854009812123456789123",
    "AE070331234567890123456",
    "AE460090000000123456789",
    "SA0380000000608010167519",
    "SA4420000001234567891234",
    "QA58DOHB00001234567890ABCDEFG",
    "QA54QNBA000000000000693123456",
    "TR330006100519786457841326",
    "TR320010009999901234567890",
    "IL620108000000099999999",
    "IL170108000000012612345",
    "GE29NB0000000101904917",
    "GE60NB0000000123456789",
    "KZ86125KZT5004100100",
    "KZ563190000012344567",
    "XK051212012345678906",
    "XK051000000000000053",
    "AL47212110090000000235698741",
    "AL35202111090000000001234567",
    "AZ21NABZ00000000137010001944",
    "AZ96AZEJ00000000001234567890",
    "BH67BMAG00001299123456",
    "BH02CITI00001077181611",
    "BR1800360305000010009795493C1",
    "BR1500000000000010932840814P2",
    "CR05015202001026284066",
    "CR23015108410026012345",
    "DO28BAGR00000001212453611324",
    "DO22ACAU00000000000123456789",
    "EG380019000500000000263180002",
    "EG800002000156789012345180002",
    "GI75NWBK000000007099453",
    "GI04BARC000001234567890",
    "GL8964710001000206",
    "GL8964710123456789",
    "GT82TRAJ01020000001210029690",
    "GT20AGRO00000000001234567890",
    "IQ98NBIQ850123456789012",
    "JO94CBJO0010000000000131000302",
    "JO71CBJO0000000000001234567890",
    "KW81CBKU0000000000001234560101",
    "LB62099900000001001901229114",
    "LB92000700000000123123456123",
    "LC55HEMM000100010012001200023015",
    "LC14BOSL123456789012345678901234",
    "MD24AG000225100013104168",
    "MD21EX000000000001234567",
    "ME25505000012345678951",
    "MK07250120000058984",
    "MK07200002785123453",
    "MR1300020001010000123456753",
    "MU17BOMM0101101030300200000MUR",
    "MU43BOMM0101123456789101000MUR",
    "PK36SCBL0000001123456702",
    "PK70BANK0000123456789000",
    "PS92PALS000000000400123456702",
    "RS35260005601001611379",
    "RS35105008123123123173",
    "SC18SSCB11010000000000001497USD",
    "SC52BAHL01031234567890123456USD",
    "ST68000100010051845310112",
    "ST23000200000289355710148",
    "SV62CENR00000000000000700025",
    "SV43ACAT00000000000000123123",
    "TL380080012345678910157",
    "TN5910006035183598478831",
    "TN5904018104004942712345",
    "UA213223130000026007233566001",
    "UA903052992990004149123456789",
    "VA59001123000012345678",
    "VG07ABVI0000000123456789",
    "BY13NBRB3600900000002Z00AB00",
    "BY86AKBB10100000002966000000",
    "FO6264600001631634",
    "FO9264600123456789",
    "LY83002048000020100120361",
    "SD2129010501234001",
    "SO211000001001000100141",
    "BI4210000100010000332045181",
    "DJ2100010000000154000100186",
    "FK88SC123456789012",
    "MN121234123456789123",
    "NI45BAPR00000013000003558124",
    "OM810180000001299123456",
    "RU0204452560040702810412345678901",
    "YE15CBYE0001018861234567891234",
];

/// Cloud / SaaS example credentials lifted from vendor docs and the
/// jwt.io / bitcoin wiki defaults.
const TEST_TOKENS: &[&str] = &[
    // AWS's documented example keys all carry the literal `EXAMPLE` and are
    // covered by the substring rule below, so they are not listed here —
    // and neither is anything shaped like a live provider key, which
    // GitHub push protection would (rightly) refuse to let this file carry.
    // Slack docs.
    "xoxb-not-a-real-token-this-will-not-work",
    // jwt.io default token.
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    // Bitcoin: genesis coinbase, the 21-leading-zero-bytes edge case, and the
    // wiki's sample P2PKH address.
    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "1111111111111111111114oLvT2",
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    // Ethereum: the zero address and the docs' sample.
    "0x0000000000000000000000000000000000000000",
    "0xb794f5ea0ba39494ce839613fffba74279579268",
];

fn strip_separators(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

/// True when `matched` is a published test/example value for `detector_id`.
pub fn is_known_example(detector_id: &str, matched: &str) -> bool {
    if detector_id.starts_with("credit_card_") {
        let pan = strip_separators(matched);
        // Stripe's whole decline / 3DS / regional catalogue lives under the
        // `4000 00` prefix; no issuer puts real cards there.
        if pan.starts_with("400000") {
            return true;
        }
        // Sixteen digits made of one four-digit block repeated four times
        // (`4242…`, `1234 1234 1234 1234`) is a keyboard test, never a card.
        if pan.len() == 16
            && pan[..4] == pan[4..8]
            && pan[..4] == pan[8..12]
            && pan[..4] == pan[12..]
        {
            return true;
        }
        return TEST_CARDS.contains(&pan.as_str());
    }
    if detector_id == "iban" {
        let iban = strip_separators(matched).to_ascii_uppercase();
        return TEST_IBANS.contains(&iban.as_str());
    }
    // Everything else: exact match, plus vendors' habit of spelling it out.
    TEST_TOKENS.contains(&matched)
        || matched.contains("EXAMPLE")
        || matched.contains("SANITAI_FAKE")
        || is_single_repeated_char(matched)
        || has_repeated_tail(matched, 12)
}

/// `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, `AKIAZZZZZZZZZZZZZZZZ`,
/// `sk-ant-api03-…xxxx`: a real credential never ends in a dozen identical
/// characters; a placeholder almost always does.
fn has_repeated_tail(s: &str, min_run: usize) -> bool {
    let mut it = s.chars().rev();
    let Some(last) = it.next() else {
        return false;
    };
    if !last.is_ascii_alphanumeric() {
        return false;
    }
    1 + it.take_while(|&c| c == last).count() >= min_run
}

/// `xxxxxxxxxxxxxxxx`, `0000000000000000`: shape of a redaction, not a secret.
fn is_single_repeated_char(s: &str) -> bool {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut chars = s.chars().filter(|c| c.is_ascii_alphanumeric());
    match chars.next() {
        Some(first) => s.len() >= 8 && chars.all(|c| c == first),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stripe_and_classic_test_cards_are_examples() {
        assert!(is_known_example("credit_card_visa", "4242424242424242"));
        assert!(is_known_example("credit_card_visa", "4242 4242 4242 4242"));
        assert!(is_known_example("credit_card_visa", "4111-1111-1111-1111"));
        assert!(is_known_example("credit_card_visa", "4000000000003220"));
        assert!(is_known_example(
            "credit_card_mastercard",
            "5555555555554444"
        ));
        assert!(is_known_example(
            "credit_card_mastercard",
            "2221000000000009"
        ));
        assert!(is_known_example("credit_card_amex", "378282246310005"));
        // A Luhn-valid number that is not on any vendor's test list.
        assert!(!is_known_example("credit_card_visa", "4539578763621486"));
    }

    #[test]
    fn registry_sample_ibans_are_examples() {
        assert!(is_known_example("iban", "GB82WEST12345698765432"));
        assert!(is_known_example("iban", "GB82 WEST 1234 5698 7654 32"));
        assert!(is_known_example("iban", "de89370400440532013000"));
        assert!(!is_known_example("iban", "GB29NWBK60161331926820"));
    }

    #[test]
    fn vendor_doc_tokens_are_examples() {
        assert!(is_known_example(
            "aws_access_key_id",
            "AKIAIOSFODNN7EXAMPLE"
        ));
        assert!(is_known_example(
            "bitcoin_address",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        ));
        assert!(is_known_example(
            "ethereum_address",
            "0x0000000000000000000000000000000000000000"
        ));
        assert!(is_known_example(
            "hex_secret",
            "ffffffffffffffffffffffffffffffff"
        ));
        assert!(is_known_example(
            "github_pat",
            "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        ));
        assert!(is_known_example(
            "aws_access_key_id",
            "AKIAZZZZZZZZZZZZZZZZ"
        ));
        assert!(!is_known_example(
            "aws_access_key_id",
            "AKIAJ5Q3Z7MX4PB2LQ9K"
        ));
        assert!(!is_known_example(
            "generic_password_assignment",
            "password=Xq9vR2mK4nL8"
        ));
    }
}
