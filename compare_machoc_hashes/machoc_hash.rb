#!/usr/bin/env ruby
# encoding: ASCII-8BIT

# TODO: Allow metasm path to be dynamic
# TODO: Release as open source package

require '/home/sturla/tools/polichombr/metasm/metasm'
include Metasm

if ARGV.length != 1
    abort "Usage: machoke_hash.rb <path/to/pe_executable.exe>"
end

target = ARGV[0]

class MurmurHash
	MASK32 = 0xffffffff
	def self.murmur3_32_rotl(x, r)
		((x << r) | (x >> (32 - r))) & MASK32
	end

	def self.murmur3_32_fmix(h)
		h &= MASK32
		h ^= h >> 16
		h = (h * 0x85ebca6b) & MASK32
		h ^= h >> 13
		h = (h * 0xc2b2ae35) & MASK32
		h ^ (h >> 16)
	end

	def self.murmur3_32__mmix(k1)
		k1 = (k1 * 0xcc9e2d51) & MASK32
		k1 = murmur3_32_rotl(k1, 15)
		(k1 * 0x1b873593) & MASK32
	end

	def self.murmur3_32_str_hash(str, seed = 0)
		h1 = seed
		numbers = str.unpack('V*C*')
		tailn = str.bytesize % 4
		tail = numbers.slice!(numbers.size - tailn, tailn)
		for k1 in numbers
    		h1 ^= murmur3_32__mmix(k1)
    		h1 = murmur3_32_rotl(h1, 13)
    		h1 = (h1 * 5 + 0xe6546b64) & MASK32
	    end
	
    	unless tail.empty?
    		k1 = 0
    		tail.reverse_each do |c1|
    			k1 = (k1 << 8) | c1
    		end
    		h1 ^= murmur3_32__mmix(k1)
    	end

	    h1 ^= str.bytesize
	    murmur3_32_fmix(h1)
    end
end

class MachocHash
    def self.calculate_machoc_hash(dasm)
        @fullFuncSign = ''
        @fullHashSign = ''
        @listoffunct = []

        dasm.function.each do |addr, _symb|
            @listoffunct << addr if addr.to_s =~ /^[0-9]+$/
        end
        @listoffunct = @listoffunct.sort
        @listoffunct .each do |addr|
            next unless addr.to_s =~ /^[0-9]+$/
            i = 1
            currFunc = ''
            @treefunc = dasm.each_function_block(addr)
            @treefunc = @treefunc.sort
            @treetbfunc = []
            @treefunc.each do |b|
            @treetbfunc << b
            end
            @treefunc.each do |bloc|
            currFunc += "#{i}:"
            dasm.di_at(bloc[0]).block.list.each do |di|
                currFunc += 'c' if di.opcode.name == 'call'
            end
            refs = bloc[1]
            refs = refs.sort
            refs.each do |to_ref|
                for y in 0..@treetbfunc.length
                next if @treetbfunc[y].nil?
                currFunc += ',' if (to_ref == @treetbfunc[y][0]) && (currFunc[-1] != ',') && (currFunc[-1] != ':')
                currFunc += (y + 1).to_s.to_s if to_ref == @treetbfunc[y][0]
                end
            end
            i += 1
            currFunc += ';'
            end
            @fullFuncSign += currFunc
            @fullHashSign += format('%08x', MurmurHash.murmur3_32_str_hash(currFunc)) + ":#{addr.to_s(16)};"
        end
        @fullHashSign
    end
end    

# load binary
decodedfile = AutoExe.decode_file(target)
entrypoints = decodedfile.get_default_entrypoints
dasm = decodedfile.disassembler
$gdasm = dasm

# disassemble the code

puts '  [*] Fast disassemble of binary...' if defined?($VERBOSEOPT)
dasm.disassemble_fast_deep(*entrypoints)

puts '  [*] Crawling uncovered code...' if defined?($VERBOSEOPT)

codePatterns = ["\x8b\xff",
                "\x55\x8b\xec",
                "\x55\x89\xe5",
                "\xff\x25",
                "\xff\x15",
                /\x68....\xe8/n,
                "\x48\x83\xec",
                "\x48\x89\x5c\x24",
                "\x55\x48\x8B\xec", # push rbp; mov rbp, rsp;
                # "\x40\x55\x41\x54\x41\x55", # push    rbp;push    r12;push   r13
                "\x40\x55"] # push    rbp

@treefuncs = []

dasm.sections.each do |secAddr, secDatas|
    next if dasm.decoded.first.nil?
    next unless (secAddr <= dasm.decoded.first[0]) && ((secAddr + secDatas.data.length) > dasm.decoded.first[0])
    codePatterns.each do |pattern|
        i = 0
        while i < secDatas.data.length
        bi = i
        pattAddr = secDatas.data[i..-1].index(pattern)
        unless pattAddr.nil?
            if dasm.di_at(secAddr + i + pattAddr).nil?
            puts "    [+] Pattern found at 0x#{(secAddr + i + pattAddr).to_s(16)} fast disassembling in process..." if defined?($VERBOSEOPT)
            dasm.disassemble_fast_deep(secAddr + i + pattAddr)
            end
            if dasm.function[secAddr + i + pattAddr].nil?
            if dasm.di_at(secAddr + i + pattAddr).block.from_subfuncret.nil? && dasm.di_at(secAddr + i + pattAddr).block.from_normal.nil?
                dasm.function[secAddr + i + pattAddr] = (dasm.function[:default] || dasm.DecodedFunction.new).dup
                dasm.function[secAddr + i + pattAddr].finalized = true
            end
            dasm.disassemble_fast_checkfunc(secAddr + i + pattAddr)
            end
            i += pattAddr + 1
        end
        i = secDatas.data.length if bi == i
        end
    end
end

dasm.function.each do |addr, _symb|
    next unless addr.to_s =~ /^[0-9]+$/
    toaddr = []
    fromaddr = []
    xreftree = dasm.get_xrefs_x(dasm.di_at(addr))
    xreftree.each do |xref_addr|
        fromaddr << xref_addr if xref_addr.to_s =~ /^[0-9]+$/
    end
    dasm.each_function_block(addr).each do |bloc|
        dasm.di_at(bloc[0]).block.list.each do |di|
        toaddr << dasm.normalize(di.instruction.args.first) if (di.opcode.name == 'call') && dasm.normalize(di.instruction.args.first).to_s =~ /^[0-9]+$/
        end
    end
    toaddr = toaddr.sort.uniq
    fromaddr = fromaddr.sort.uniq
    @treefuncs << [addr, toaddr, fromaddr]
    end
    entrypoints.each do |ep|
    next unless $gdasm.function[dasm.normalize(ep)].nil?
    toaddr = []
    fromaddr = []
    next unless !dasm.di_at(dasm.normalize(ep)).nil? && !dasm.di_at(dasm.normalize(ep)).instruction.nil?
    xreftree = dasm.get_xrefs_x(dasm.di_at(dasm.normalize(ep)))
    xreftree.each do |xref_addr|
        fromaddr << xref_addr if xref_addr.to_s =~ /^[0-9]+$/
    end
    dasm.each_function_block(dasm.normalize(ep)).each do |bloc|
        dasm.di_at(bloc[0]).block.list.each do |di|
        toaddr << dasm.normalize(di.instruction.args.first) if (di.opcode.name == 'call') && dasm.normalize(di.instruction.args.first).to_s =~ /^[0-9]+$/
        end
    end
    toaddr = toaddr.sort.uniq
    fromaddr = fromaddr.sort.uniq
    @treefuncs << [dasm.normalize(ep), toaddr, fromaddr]
end

fullHashSign = MachocHash.calculate_machoc_hash(dasm)

puts fullHashSign
