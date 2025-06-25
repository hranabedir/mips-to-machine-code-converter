import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.*;

public class MIPSConverterGUI {

    // Maps MIPS register names to their 5-bit binary representation
    private static final Map<String, String> registerMap = new HashMap<>();
    // Maps MIPS instruction mnemonics to their opcode (for I-type and J-type)
    private static final Map<String, String> opcodeMap = new HashMap<>();
    // Maps MIPS R-type instruction mnemonics to their 6-bit function code
    private static final Map<String, String> functMap = new HashMap<>();

    static {
        // Initialize register map
        registerMap.put("$zero", "00000"); registerMap.put("$0", "00000");
        registerMap.put("$at", "00001"); registerMap.put("$1", "00001");
        registerMap.put("$v0", "00010"); registerMap.put("$2", "00010");
        registerMap.put("$v1", "00011"); registerMap.put("$3", "00011");
        registerMap.put("$a0", "00100"); registerMap.put("$4", "00100");
        registerMap.put("$a1", "00101"); registerMap.put("$5", "00101");
        registerMap.put("$a2", "00110"); registerMap.put("$6", "00110");
        registerMap.put("$a3", "00111"); registerMap.put("$7", "00111");
        registerMap.put("$t0", "01000"); registerMap.put("$8", "01000");
        registerMap.put("$t1", "01001"); registerMap.put("$9", "01001");
        registerMap.put("$t2", "01010"); registerMap.put("$10", "01010");
        registerMap.put("$t3", "01011"); registerMap.put("$11", "01011");
        registerMap.put("$t4", "01100"); registerMap.put("$12", "01100");
        registerMap.put("$t5", "01101"); registerMap.put("$13", "01101");
        registerMap.put("$t6", "01110"); registerMap.put("$14", "01110");
        registerMap.put("$t7", "01111"); registerMap.put("$15", "01111");
        registerMap.put("$s0", "10000"); registerMap.put("$16", "10000");
        registerMap.put("$s1", "10001"); registerMap.put("$17", "10001");
        registerMap.put("$s2", "10010"); registerMap.put("$18", "10010");
        registerMap.put("$s3", "10011"); registerMap.put("$19", "10011");
        registerMap.put("$s4", "10100"); registerMap.put("$20", "10100");
        registerMap.put("$s5", "10101"); registerMap.put("$21", "10101");
        registerMap.put("$s6", "10110"); registerMap.put("$22", "10110");
        registerMap.put("$s7", "10111"); registerMap.put("$23", "10111");
        registerMap.put("$t8", "11000"); registerMap.put("$24", "11000");
        registerMap.put("$t9", "11001"); registerMap.put("$25", "11001");
        registerMap.put("$k0", "11010"); registerMap.put("$26", "11010");
        registerMap.put("$k1", "11011"); registerMap.put("$27", "11011");
        registerMap.put("$gp", "11100"); registerMap.put("$28", "11100");
        registerMap.put("$sp", "11101"); registerMap.put("$29", "11101");
        registerMap.put("$fp", "11110"); registerMap.put("$30", "11110");
        registerMap.put("$ra", "11111"); registerMap.put("$31", "11111");

        // R-Type instruction opcodes are all "000000", funct codes vary
        functMap.put("add", "100000");
        functMap.put("sub", "100010");
        functMap.put("and", "100100");
        functMap.put("or", "100101");
        functMap.put("sll", "000000");
        functMap.put("srl", "000010");
        functMap.put("sllv", "000100");
        functMap.put("srlv", "000110");
        // JR is also R-type: funct "001000", uses only rs. Not in spec but common.

        // I-Type instruction opcodes
        opcodeMap.put("addi", "001000");
        opcodeMap.put("andi", "001100"); // Immediate is zero-extended
        opcodeMap.put("lw", "100011");
        opcodeMap.put("sw", "101011");
        opcodeMap.put("beq", "000100");
        opcodeMap.put("bne", "000101");
        opcodeMap.put("blez", "000110"); // rt is $zero (00000)
        opcodeMap.put("bgtz", "000111"); // rt is $zero (00000)

        // J-Type instruction opcodes
        opcodeMap.put("j", "000010");
        opcodeMap.put("jal", "000011");
    }

    private JTextArea inputArea;
    private JTextArea outputArea;
    private JTextField startAddressField;

    // Helper class to store information about each line of assembly
    static class AssemblyEntry {
        String originalLine;    // The raw line from input
        String instructionText; // The MIPS instruction part (e.g., "add $t0, $s0, $s1")
        int address;            // Address if it's an instruction or a label definition line
        boolean isInstruction;  // True if instructionText is a valid instruction to be assembled

        AssemblyEntry(String original, String text, int addr, boolean isInstr) {
            this.originalLine = original;
            this.instructionText = text;
            this.address = addr;
            this.isInstruction = isInstr;
        }
    }


    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            MIPSConverterGUI converter = new MIPSConverterGUI();
            converter.createAndShowGUI();
        });
    }

    private void createAndShowGUI() {
        JFrame frame = new JFrame("MIPS to Machine Code Converter");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(850, 700); // Adjusted size
        frame.setLayout(new BorderLayout(5, 5));

        // Top panel for start address and convert button
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(new JLabel("Start Address (hex):"));
        startAddressField = new JTextField("00400000", 10);
        topPanel.add(startAddressField);
        JButton convertButton = new JButton("Convert");
        topPanel.add(convertButton);
        frame.add(topPanel, BorderLayout.NORTH);

        // Input area for MIPS assembly
        inputArea = new JTextArea();
        inputArea.setFont(new Font("Monospaced", Font.PLAIN, 14));
        JScrollPane inputScrollPane = new JScrollPane(inputArea);
        inputScrollPane.setBorder(BorderFactory.createTitledBorder("MIPS Assembly Code"));

        // Output area for machine code
        outputArea = new JTextArea();
        outputArea.setFont(new Font("Monospaced", Font.PLAIN, 14));
        outputArea.setEditable(false);
        JScrollPane outputScrollPane = new JScrollPane(outputArea);
        outputScrollPane.setBorder(BorderFactory.createTitledBorder("Address & Machine Code"));
        
        // Split pane to hold input and output areas
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, inputScrollPane, outputScrollPane);
        splitPane.setResizeWeight(0.5); // Distribute space equally
        frame.add(splitPane, BorderLayout.CENTER);

        convertButton.addActionListener(e -> convertMipsCode());

        frame.setLocationRelativeTo(null); // Center the frame
        frame.setVisible(true);
    }

    private void convertMipsCode() {
        outputArea.setText(""); // Clear previous output
        String assemblyProgram = inputArea.getText();
        if (assemblyProgram.trim().isEmpty()) {
            outputArea.setText("Input MIPS code is empty.");
            return;
        }

        long initialAddress;
        try {
            initialAddress = Long.parseLong(startAddressField.getText().trim(), 16);
        } catch (NumberFormatException nfe) {
            outputArea.setText("Error: Invalid Start Address format. Please use hexadecimal (e.g., 00400000).");
            return;
        }

        String[] lines = assemblyProgram.split("\\r?\\n");
        Map<String, Integer> labelMap = new HashMap<>();
        List<AssemblyEntry> assemblyEntries = new ArrayList<>();
        int currentAddressCounter = (int) initialAddress;

        // --- First Pass: Populate labelMap and prepare assembly entries ---
        for (String rawLine : lines) {
            String processedLine = rawLine;
            int commentIdx = processedLine.indexOf('#'); // Remove comments
            if (commentIdx != -1) {
                processedLine = processedLine.substring(0, commentIdx);
            }
            processedLine = processedLine.trim();

            if (processedLine.isEmpty()) {
                if (!rawLine.trim().isEmpty()) { 
                     assemblyEntries.add(new AssemblyEntry(rawLine, "", -1, false));
                }
                continue;
            }

            String label = null;
            String instructionText = processedLine;

            if (processedLine.contains(":")) {
                label = processedLine.substring(0, processedLine.indexOf(":")).trim();
                instructionText = processedLine.substring(processedLine.indexOf(":") + 1).trim();
                if (labelMap.containsKey(label)) {
                     outputArea.setText("Error: Duplicate label '" + label + "'.");
                     return;
                }
                labelMap.put(label, currentAddressCounter);
            }

            if (!instructionText.isEmpty()) {
                assemblyEntries.add(new AssemblyEntry(rawLine, instructionText, currentAddressCounter, true));
                currentAddressCounter += 4; // Each MIPS instruction is 4 bytes
            } else { 
                assemblyEntries.add(new AssemblyEntry(rawLine, "", (label != null ? labelMap.get(label) : -1), false));
            }
        }

        // --- Second Pass: Assemble instructions and build output string ---
        StringBuilder outputBuilder = new StringBuilder();
        outputBuilder.append(String.format("%-45s %-12s %s\n", "MIPS Assembly", "Address", "Machine Code (Hex)"));
        outputBuilder.append("-".repeat(75) + "\n"); 


        for (AssemblyEntry entry : assemblyEntries) {
            if (entry.isInstruction) {
                String binaryCode;
                try {
                    binaryCode = assembleInstructionLine(entry.instructionText, entry.address, labelMap, (int)initialAddress);
                } catch (IllegalArgumentException | ArithmeticException | IndexOutOfBoundsException ex) { // Catch more specific exceptions
                    binaryCode = "Error: " + ex.getMessage();
                }
                
                String hexCode = "Error";
                if (binaryCode.length() == 32 && !binaryCode.startsWith("Error:")) {
                     hexCode = binaryToHex(binaryCode);
                } else if (binaryCode.startsWith("Error:")) {
                    hexCode = binaryCode; 
                }


                String originalMipsLine = entry.originalLine;
                int commentPos = originalMipsLine.indexOf('#');
                if (commentPos != -1) originalMipsLine = originalMipsLine.substring(0, commentPos);
                originalMipsLine = originalMipsLine.trim();

                outputBuilder.append(String.format("%-45s %-12s %s\n",
                        originalMipsLine,
                        String.format("0x%08X", entry.address),
                        hexCode.startsWith("Error:") ? hexCode : "0x" + hexCode));
            } else {
                String trimmedOriginal = entry.originalLine.trim();
                if (!trimmedOriginal.isEmpty()) { 
                    outputBuilder.append(String.format("%-45s\n", entry.originalLine));
                }
            }
        }
        outputArea.setText(outputBuilder.toString());
    }

    // Assembles a single MIPS instruction line to its 32-bit binary representation
    private String assembleInstructionLine(String instruction, int currentPc, Map<String, Integer> labelMap, int baseAddress) {
        String[] parts = instruction.toLowerCase().replaceAll(",", " ").trim().split("\\s+");
        String mnemonic = parts[0];

        // R-Type instructions
        if (functMap.containsKey(mnemonic)) {
            String funct = functMap.get(mnemonic);
            String rs = "00000", rt = "00000", rd = "00000", shamt = "00000";
            if (mnemonic.equals("sll") || mnemonic.equals("srl")) { 
                if (parts.length != 4) throw new IllegalArgumentException("Invalid operands for " + mnemonic + ". Expected format: " + mnemonic + " $rd, $rt, shamt");
                rd = getRegister(parts[1]);
                rt = getRegister(parts[2]);
                shamt = formatImmediate(Integer.parseInt(parts[3]), 5, false); 
                rs = "00000"; 
            } else if (mnemonic.equals("sllv") || mnemonic.equals("srlv")) { 
                 if (parts.length != 4) throw new IllegalArgumentException("Invalid operands for " + mnemonic + ". Expected format: " + mnemonic + " $rd, $rt, $rs");
                rd = getRegister(parts[1]);
                rt = getRegister(parts[2]); // Note: MIPS format is rd, rs, rt for sllv/srlv in some docs, but usually rd, rt, rs. Assuming rd, rt, rs as per common use.
                rs = getRegister(parts[3]); // If standard is rd, rs, rt, then rt and rs here should be swapped.
                                            // For this code, we'll stick to the order in the user's example input if it implies one.
                                            // Assuming parts are [mnemonic, rd, rt, rs] for sllv/srlv
                shamt = "00000";
            } else { 
                if (parts.length != 4) throw new IllegalArgumentException("Invalid operands for " + mnemonic + ". Expected format: " + mnemonic + " $rd, $rs, $rt");
                rd = getRegister(parts[1]);
                rs = getRegister(parts[2]);
                rt = getRegister(parts[3]);
            }
            return "000000" + rs + rt + rd + shamt + funct;
        }
        // I-Type and J-Type instructions
        else if (opcodeMap.containsKey(mnemonic)) {
            String opcode = opcodeMap.get(mnemonic);
            String rs = "00000", rt = "00000", immediate = "";

            if (mnemonic.equals("addi") || mnemonic.equals("andi")) { 
                if (parts.length != 4) throw new IllegalArgumentException("Invalid operands for " + mnemonic + ". Expected format: " + mnemonic + " $rt, $rs, imm");
                rt = getRegister(parts[1]);
                rs = getRegister(parts[2]);
                boolean zeroExtend = mnemonic.equals("andi"); 
                immediate = formatImmediate(parseImmediate(parts[3]), 16, !zeroExtend);
                return opcode + rs + rt + immediate;
            }
            // lw rt, offset(rs)  OR sw rt, offset(rs)
            else if (mnemonic.equals("lw") || mnemonic.equals("sw")) {
                if (parts.length != 3) throw new IllegalArgumentException("Invalid operands for " + mnemonic + ". Expected format: " + mnemonic + " $rt, offset($rs)");
                rt = getRegister(parts[1]);
                
                String memOperand = parts[2]; // e.g., "16($s0)" or "-4($zero)"
                int openParenIndex = memOperand.indexOf('(');
                int closeParenIndex = memOperand.indexOf(')');

                if (openParenIndex == -1 || closeParenIndex == -1 || openParenIndex >= closeParenIndex || closeParenIndex != memOperand.length() - 1) {
                    throw new IllegalArgumentException("Invalid memory operand format for " + mnemonic + ": " + memOperand + ". Expected offset($rs).");
                }

                String offsetStr = memOperand.substring(0, openParenIndex).trim();
                String baseRegStr = memOperand.substring(openParenIndex + 1, closeParenIndex).trim();

                if (offsetStr.isEmpty() || baseRegStr.isEmpty()) {
                    throw new IllegalArgumentException("Empty offset or base register in memory operand for " + mnemonic + ": " + memOperand);
                }
                
                try {
                    immediate = formatImmediate(parseImmediate(offsetStr), 16, true); // Offset is signed
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid numeric offset in memory operand for " + mnemonic + ": " + offsetStr);
                }
                rs = getRegister(baseRegStr); // Base register
                return opcode + rs + rt + immediate;
            }
            // beq rs, rt, label OR bne rs, rt, label
            else if (mnemonic.equals("beq") || mnemonic.equals("bne")) {
                if (parts.length != 4) throw new IllegalArgumentException("Invalid operands for " + mnemonic + ". Expected format: " + mnemonic + " $rs, $rt, label");
                rs = getRegister(parts[1]);
                rt = getRegister(parts[2]);
                if (!labelMap.containsKey(parts[3])) throw new IllegalArgumentException("Label not found: " + parts[3] + " for instruction at PC " + String.format("0x%08X", currentPc));
                int targetAddress = labelMap.get(parts[3]);
                int offset = (targetAddress - (currentPc + 4)) / 4; 
                immediate = formatImmediate(offset, 16, true);
                return opcode + rs + rt + immediate;
            }
            // blez rs, label OR bgtz rs, label
            else if (mnemonic.equals("blez") || mnemonic.equals("bgtz")) {
                if (parts.length != 3) throw new IllegalArgumentException("Invalid operands for " + mnemonic + ". Expected format: " + mnemonic + " $rs, label");
                rs = getRegister(parts[1]);
                rt = "00000"; 
                if (!labelMap.containsKey(parts[2])) throw new IllegalArgumentException("Label not found: " + parts[2] + " for instruction at PC " + String.format("0x%08X", currentPc));
                int targetAddress = labelMap.get(parts[2]);
                int offset = (targetAddress - (currentPc + 4)) / 4;
                immediate = formatImmediate(offset, 16, true);
                return opcode + rs + rt + immediate;
            }
            // j label OR jal label
            else if (mnemonic.equals("j") || mnemonic.equals("jal")) {
                if (parts.length != 2) throw new IllegalArgumentException("Invalid operands for " + mnemonic + ". Expected format: " + mnemonic + " label");
                if (!labelMap.containsKey(parts[1])) throw new IllegalArgumentException("Label not found: " + parts[1] + " for instruction at PC " + String.format("0x%08X", currentPc));
                int targetAddress = labelMap.get(parts[1]);
                int jumpTargetField = (targetAddress >>> 2) & 0x03FFFFFF; 
                immediate = formatImmediate(jumpTargetField, 26, false); 
                return opcode + immediate;
            }
        }
        throw new IllegalArgumentException("Unknown or unsupported instruction: " + mnemonic + " (at PC " + String.format("0x%08X", currentPc) + ")");
    }

    // Helper to get 5-bit register binary string
    private String getRegister(String regName) {
        String reg = registerMap.get(regName.toLowerCase());
        if (reg == null) throw new IllegalArgumentException("Unknown register: " + regName);
        return reg;
    }
    
    // Parses immediate string (decimal or hex)
    private int parseImmediate(String immStr) {
        immStr = immStr.toLowerCase().trim(); // Trim spaces
        if (immStr.startsWith("0x")) {
            if (immStr.length() == 2) throw new NumberFormatException("Hex string is empty after 0x");
            return Integer.parseInt(immStr.substring(2), 16);
        }
        if (immStr.isEmpty()) throw new NumberFormatException("Immediate string is empty");
        return Integer.parseInt(immStr);
    }


    // Helper to format an integer to a binary string of 'bits' length
    // Handles padding and two's complement for signed values if 'signed' is true
    private String formatImmediate(int value, int bits, boolean signed) {
        String binaryString;
        long mask = (1L << bits) - 1; // Mask for the desired number of bits

        if (signed) {
            if (value >= 0) {
                // Check if positive value fits
                if (value > (mask >> 1)) // Max positive for 'bits' signed is 2^(bits-1) - 1
                    
                binaryString = Long.toBinaryString(value & mask); // Apply mask to handle potential overflow if value was larger than mask but positive
                 // Ensure it's 'bits' long, pad with 0s
                while (binaryString.length() < bits) {
                    binaryString = "0" + binaryString;
                }
                if (binaryString.length() > bits) { // Should not happen if value was masked
                    binaryString = binaryString.substring(binaryString.length() - bits);
                }

            } else { // Negative value
                binaryString = Long.toBinaryString(value & mask); // Applying mask gets correct 'bits' two's complement
                if (binaryString.length() < bits) { // Should be padded with 1s if it was a high negative number that became short
                    // This path is less likely with `value & mask` for negatives if 'bits' is e.g. 16 and value is small negative
                     StringBuilder sb = new StringBuilder(binaryString);
                     while(sb.length() < bits) {
                         sb.insert(0, '1'); // Pad with 1s for negative numbers if needed (though & mask handles this)
                     }
                     binaryString = sb.toString();
                }
                 if (binaryString.length() > bits && binaryString.startsWith("1")) { // Common for Long.toBinaryString of negative numbers
                    binaryString = binaryString.substring(binaryString.length() - bits);
                } else if (binaryString.length() < bits) { // Pad if necessary, should be rare with mask
                     binaryString = String.format("%" + bits + "s", binaryString).replace(' ', '1'); // Pad with 1s for negative
                }
            }
        } else { // Unsigned
            if (value < 0) throw new IllegalArgumentException("Negative value for unsigned immediate: " + value);
            if (value > mask) { // Check if unsigned value fits
                throw new IllegalArgumentException("Unsigned immediate " + value + " too large for " + bits + " bits (max is " + mask + ").");
            }
            binaryString = Integer.toBinaryString(value);
        }

        // Pad with leading zeros to ensure 'bits' length for unsigned, or if signed result is shorter than 'bits'
        // For signed numbers, if they are negative and `Long.toBinaryString(value & mask)` produced a string shorter than `bits`
        if (binaryString.length() < bits) {
             char padChar = (signed && value < 0 && binaryString.startsWith("1")) ? '1' : '0'; // Sign-extend for negative
             // If not negative, or if negative but already has leading 1 from mask, pad with 0s.
             // Let's simplify: String.format will pad with spaces, then replace with '0'.
             // This is fine for positive numbers and correctly masked negative numbers.
            binaryString = String.format("%" + bits + "s", binaryString).replace(' ', '0');
        }
         // If after all operations, the string is longer than 'bits', truncate. This should only happen
         // if Integer.toBinaryString for a positive number was longer and wasn't masked correctly initially.
         if (binaryString.length() > bits) {
            binaryString = binaryString.substring(binaryString.length() - bits);
         }
        return binaryString;
    }


    // Converts a 32-bit binary string to its hexadecimal representation (without "0x" prefix)
    private String binaryToHex(String binary) {
        if (binary == null || !binary.matches("[01]{32}")) {
            // If an error message was passed as binary code
            if (binary != null && binary.startsWith("Error:")) return binary;
            return "Invalid Binary"; 
        }
        try {
            java.math.BigInteger bi = new java.math.BigInteger(binary, 2);
            String hex = bi.toString(16).toUpperCase();
            return String.format("%8s", hex).replace(' ', '0');
        } catch (NumberFormatException e) {
            return "Conversion Error";
        }
    }
}
