function capture = pcap2matlab(filter, decodeas_and_dissector, filename_or_interface, capture_stop_criteria)
% pcap2matlab() imports network protocol analyzer capabilties into MATLAB.
%   
%   capture = pcap2matlab(filter, decodeas_and_dissector,filename_or_interface, capture_stop_criteria) 
%   allows to perform direct network live captures as well as *.pcap files reading from the MATLAB
%   workspace. The output variable is a MATLAB structure, one entry for each captured packet, 
%   comprising the content of the packet fields that were requested by the input arguments. 
%   The function is based on the TShark network protocol analyzer (see http://www.wireshark.org/docs/man-pages/tshark.html
%   for more information) and can operate in two modes:
%       1.	Capture mode in which it starts listening on the requested network interface, capturing 
%           packets based on some predefined criteria (i.e. filter) and output the relevant packet fields
%           based on the decodeas and dissector input arguments.
%       2.	Read mode in which it reads an already existing pcap file, extract packets based on some 
%           predefined criteria (i.e. filter) and output the relevant packet fields based on the 
%           decodeas and dissector input arguments.
%   The function currently supports PC 32/64-bit as well as Linux 32/64-bit platforms. 
%   Other platforms might be easily added in the future.
% 
%   Input arguments:
%   * filter – A TShark format capture filter argument (tshark -f flag like 'net 10.10.10.4 and src port 12001') 
%           or a display filter argument (tshark –Y flag like 'ip.src==10.10.10.4 and udp.srcport==12001')
%           depending on the selected mode of operation (i.e. capture or read). 
%           For more information please revert to http://wiki.wireshark.org/CaptureFilters and
%           http://wiki.wireshark.org/DisplayFilters.
%   * decodeas_and_dissector – This input argument can be one of the following things:
%           1.	A MATLAB structure whose field names are the requested packet field names to capture 
%               whereas the content of each field, of this structure, comprises the byte offsets to 
%               capture for this specific field. The content of the structure can be one of the following:
%               (a) A MATLAB decimal vector specifying the byte offsets to capture. For example:
%
%                               decodeas_and_dissector.sn = [43 44 45 46]
%                               decodeas_and_dissector.timestamp: [47:54]
%
%                   will instruct the function to capture 2 fields named "sn" and "timestamp" with byte offsets
%                   43-46 and 47-54 respectively. The offset is calculated from the very first byte (offset 0)
%                   of the packet including the layer 2 portion (starting from the MAC destination address in 
%                   the case of an Ethernet frame). The returned value will be a decimal number representing 
%                   the total decimal value of these aggregated byte offsets. 
%               (b) A string comprising the offset bytes to capture in hexadecimal representation. For example:
%
%                               decodeas_and_dissector.sn = '43:46'
%                               decodeas_and_dissector.timestamp: '47:54'
%
%                   will instruct the function to capture 2 fields named "sn" and "timestamp" with byte offsets
%                   43-46 and 47-54 respectively. The offset is calculated from the very first byte (offset 0)
%                   of the packet including the layer 2 portion (starting from the MAC destination address in 
%                   the case of an Ethernet frame). The returned value will be a string comprising the entire
%                   content of these byte offsets (if only a single byte offset is required the colon can be 
%                   removed. For example: decodeas_and_dissector.sn = '43').
%               (c) Same as (b) with additional '/' character followed by specific BIT offsets to be extracted
%                   from the specified byte offsets (specified before the '/'). For example, the dissector lines:
%
%                               decodeas_and_dissector.firstflag = '43/0:1'
%                               decodeas_and_dissector.secondflag = '45/6'
%
%                   will instruct the function to capture MSB bits 0:1 from byte offset 43 in the 'firstflag' 
%                   field and bit 6 from byte offset 45 in the 'secondflag' field. The returned value is a 
%                   decimal number of the value of the extracted bits.
%                   
%           2.	A one-dimensional cell of strings comprising the TShark decodeas expression (TShark
%               -d flag) (not mandatory but if appears must be the first one) as well as additional 
%               TShark dissector expressions (TShark -e flag). Each dissector expression will
%               results in a matching field in the output captured struct. 
%               For example: the following cell of strings
%               {'tcp.port==8888,http';'frame.number';'frame.time';'tcp.length';'tcp.srcport'}
%               will instruct the function to decode the captured packet with TCP port 8888 as http. 
%               Then, extracting the following 4 fields from each captured packet: frame.number, 
%               frame.time, tcp.length and tcp.srcport to the output capture struct:
% 
%                                           capture =
%                                           1x97 struct array with fields:
%                                                       framenumber
%                                                       frametime
%                                                       tcplength
%                                                       tcpsrcport
% 
%       For more information on TShark’s decodeas and dissection fields options please refer to:
%       http://www.wireshark.org/docs/man-pages/tshark.html
%   * filename_or_interface – This input argument can be one of two things:
%           1.	An integer number that identifies the network interface from which to start 
%               capturing (TShark -i flag). Setting this input argument to an integer number will
%               automatically set the function to work in capture mode.
%           2.	A filename string that identifies the pcap file to read. Setting this input argument 
%               to a filename string will automatically set the function to work in read mode.
%   * capture_stop_criteria – Relevant for capture mode only (should not be assigned when working in
%           read mode). Sets the capture ‘stop capturing’ criteria (TShark -a/-c flags). This input 
%           argument can be one of the following things:
%           1. A numeric number that sets the total number of packets to capture (TShark -c flag). 
%           2. A string that identifies the capture stop criteria (TShark -a flag).
%           3. A cell array combining a few legal capture stop criteria arguments such as 
%               {'duration:10',100} that will stop capturing after 10 sec or 100 packets whichever 
%               comes first. 
%           For more information on TShark’s stop capturing criteria options please refer to:
%           http://www.wireshark.org/docs/man-pages/tshark.html.
% 
%   Alon Geva
%   $Revision: 1.03 $  $Date: 25/04/2014 01:52:53 $

OS = computer;
WSdissector_FLAG = iscell(decodeas_and_dissector);
capture_FLAG = ~ischar(filename_or_interface);

switch OS
    case {'PCWIN','PCWIN32','PCWIN64'}
%         os_cmd = 'dos';
        separator_char = ';';
    case {'GLNXA64','GLNX86'}
%         os_cmd = 'unix';
        separator_char = '\;';
end

if ~isempty(filter)
    capture_filter_str = [' -f "' filter '"'];
    read_filter_str = [' -Y "' filter '"'];
else
    capture_filter_str = '';
    read_filter_str = '';
end

capture_stop_str = [];
if exist('capture_stop_criteria','var')
    if iscell(capture_stop_criteria)
        for idx=1:numel(capture_stop_criteria),
            if isnumeric(capture_stop_criteria{idx})
                capture_stop_str = [capture_stop_str ' -c ' num2str(capture_stop_criteria{idx})];
            else
                capture_stop_str = [capture_stop_str ' -a ' capture_stop_criteria{idx}];
            end
        end
    else
        if isnumeric(capture_stop_criteria)
            capture_stop_str = [' -c ' num2str(capture_stop_criteria)];
        else
            capture_stop_str = [' -a ' capture_stop_criteria];
        end
    end
end

if (capture_FLAG) % capture mode
    fprintf(['Started capturing from network interface #' int2str(filename_or_interface) ':\n']);
%     eval(['status=' os_cmd '(''tshark -i ' int2str(filename_or_interface) capture_stop_str ' -w tmp.pcap' capture_filter_str ''');'])
    eval(['status=system(''tshark -i ' int2str(filename_or_interface) capture_stop_str ' -w tmp.pcap' capture_filter_str ''');'])

    assert(~status,'Capture using Tshark did not run well. Please make sure your inputs were correct.')
    read_filename = 'tmp.pcap';
else
    read_filename = filename_or_interface;
end

if (~WSdissector_FLAG) % using MATLAB defined disssector
    fprintf('Started reading captured file:\n');
    if (capture_FLAG)
        eval(['status=system(''tshark -r ' read_filename ' -F k12text -w tmp.txt'');'])
    else
        eval(['status=system(''tshark -r ' read_filename ' -F k12text' read_filter_str ' -w tmp.txt'');'])
    end
    assert(~status,'Reading capture using Tshark did not run well. Please make sure your inputs were correct.')

else
    usingdecodeas_FLAG = ~isempty(regexp(decodeas_and_dissector{1},'==','ONCE'));
    if usingdecodeas_FLAG
        decodeas_str = [' -d ' decodeas_and_dissector{1}];
    else
        decodeas_str = '';
    end
    
    FieldsofDissector = decodeas_and_dissector(1+usingdecodeas_FLAG:end);
    SizeofDissector = max(size(FieldsofDissector));
    WSdissector_str = [];
    for idx=1:SizeofDissector,
        WSdissector_str = [WSdissector_str ' -e ' FieldsofDissector{idx} ' '];
    end
 
    if (capture_FLAG)
        eval(['status=system(''tshark -r ' read_filename decodeas_str ' -T fields -E separator=' separator_char  WSdissector_str ' > tmp.txt '');'])
    else
        eval(['status=system(''tshark -r ' read_filename decodeas_str ' -T fields -E separator=' separator_char  WSdissector_str  read_filter_str ' > tmp.txt '');'])
    end
    assert(~status,'Reading capture using Tshark did not run well. Please make sure your inputs were correct.')
end
    
FILEREADBLOCKSIZE = 10000; % MUST be a multiple of 5 derived from K12text file format.
    
fprintf('Started importing to MATLAB:\n');

if (~WSdissector_FLAG) % using MATLAB struct defined disssector
    
    % dissecting k12text file
    fid = fopen('tmp.txt');
    n = 0;
    while ~feof(fid)
        n = n + sum( fread( fid, 16384, 'char' ) == char(10) );
    end
    n = n / 4;
    fclose(fid);
    
%     dissector_base_FLAG = 10*ones(1,);
%     if (isfield(decodeas_and_dissector,'base'))
%         switch decodeas_and_dissector.base
%             case {'dec'}
%                 dissector_base_FLAG = 10;
%             case {'hex'}
%                 dissector_base_FLAG = 16;
%             otherwise
%                 assert('Currently the only supported dissector bases are DEC and HEX');
%         end
%         decodeas_and_dissector = rmfield(decodeas_and_dissector,'base');
%     end 
        
    FieldsofDissector = fieldnames(decodeas_and_dissector);
    SizeofDissector = max(size(FieldsofDissector));
 
    dissector_weights = cell(SizeofDissector,1);
    capture_template = struct();
    capture_template.frametime = 0;
    dissector_base_FLAG = 10*ones(1,SizeofDissector); % default is decimal base dissection

    for idx=1:SizeofDissector,
        capture_template.(FieldsofDissector{idx}) = 0; %setfield(capture,FieldsofDissector(idx),[]);
        if ischar(decodeas_and_dissector.(FieldsofDissector{idx}))
            dissector_base_FLAG(idx) = 16;
        end
        
        switch dissector_base_FLAG(idx)
            case {10}
                dissector_weights{idx,1} = 256.^(length(decodeas_and_dissector.(FieldsofDissector{idx}))-1:-1:0);
                decodeas_and_dissector.(FieldsofDissector{idx}) = decodeas_and_dissector.(FieldsofDissector{idx}) + 1; %+1 added on 15/1/14 to make the offset of the first byte 0
            case {16}
                tmp = decodeas_and_dissector.(FieldsofDissector{idx});tmp_colon = find(tmp == ':');tmp_slash = find(tmp == '/');
                
                if isempty(tmp_slash)
                    TMP_SLASH_FLAG = 0;
                    tmp_slash = length(tmp);
                else
                    TMP_SLASH_FLAG = 1;
                end                                        
                    
                if (isempty(tmp_colon))
                    TMP_COLON_FLAG = 0;        
                elseif (length(tmp_colon) == 2)
                    TMP_COLON_FLAG = 2;
                elseif (tmp_colon < tmp_slash)
                    TMP_COLON_FLAG = -1;
                else
                    TMP_COLON_FLAG = +1;
                end
                   
                % part A
                if (TMP_COLON_FLAG == -1) || (TMP_COLON_FLAG == 2)%~(isempty(tmp_colon)) && (isempty(tmp_slash))
                    decodeas_and_dissector.(FieldsofDissector{idx}) = hex2dec(tmp(1:tmp_colon(1)-1)) : hex2dec(tmp(tmp_colon(1)+1:tmp_slash-1));
                    decodeas_and_dissector.(FieldsofDissector{idx}) = reshape([decodeas_and_dissector.(FieldsofDissector{idx})*2+1;decodeas_and_dissector.(FieldsofDissector{idx})*2+2],1,length(decodeas_and_dissector.(FieldsofDissector{idx}))*2);
                else 
                    decodeas_and_dissector.(FieldsofDissector{idx}) = hex2dec(tmp(1:tmp_slash-1));
                    decodeas_and_dissector.(FieldsofDissector{idx}) = reshape([decodeas_and_dissector.(FieldsofDissector{idx})*2+1;decodeas_and_dissector.(FieldsofDissector{idx})*2+2],1,length(decodeas_and_dissector.(FieldsofDissector{idx}))*2);
                end
                % part B
                if (TMP_SLASH_FLAG)
                    if (TMP_COLON_FLAG == +1)
                        decodeas_and_dissector.(FieldsofDissector{idx}) = {decodeas_and_dissector.(FieldsofDissector{idx}), hex2dec(tmp(tmp_slash+1:tmp_colon(1)-1))+1:hex2dec(tmp(tmp_colon(1)+1:end))+1};
                    elseif (TMP_COLON_FLAG == 2)
                        decodeas_and_dissector.(FieldsofDissector{idx}) = {decodeas_and_dissector.(FieldsofDissector{idx}), hex2dec(tmp(tmp_slash+1:tmp_colon(2)-1))+1:hex2dec(tmp(tmp_colon(2)+1:end))+1};
                    else
                        decodeas_and_dissector.(FieldsofDissector{idx}) = {decodeas_and_dissector.(FieldsofDissector{idx}), hex2dec(tmp(tmp_slash+1:end))+1};
                    end
                end 
        end
    end

    
%     for idx=1:SizeofDissector,
%         capture_template.(FieldsofDissector{idx}) = 0; %setfield(capture,FieldsofDissector(idx),[]);
%         if ischar(decodeas_and_dissector.(FieldsofDissector{idx}))
%             dissector_base_FLAG(idx) = 16;
%         end
%         switch dissector_base_FLAG(idx)
%             case {10}
%                 dissector_weights{idx,1} = 256.^(length(decodeas_and_dissector.(FieldsofDissector{idx}))-1:-1:0);
%                 decodeas_and_dissector.(FieldsofDissector{idx}) = decodeas_and_dissector.(FieldsofDissector{idx}) + 1; %+1 added on 15/1/14 to make the offset of the first byte 0
%             case {16}
%                 tmp = decodeas_and_dissector.(FieldsofDissector{idx});tmp_colon = find(tmp == ':');tmp_slash = find(tmp == '/');
%                 if ~(isempty(tmp_colon)) && (isempty(tmp_slash))
%                     decodeas_and_dissector.(FieldsofDissector{idx}) = hex2dec(tmp(1:tmp_colon-1)) : hex2dec(tmp(tmp_colon+1:end));
%                     decodeas_and_dissector.(FieldsofDissector{idx}) = reshape([decodeas_and_dissector.(FieldsofDissector{idx})*2+1;decodeas_and_dissector.(FieldsofDissector{idx})*2+2],1,length(decodeas_and_dissector.(FieldsofDissector{idx}))*2);
%                 elseif (isempty(tmp_slash))
%                     decodeas_and_dissector.(FieldsofDissector{idx}) = hex2dec(tmp(1:end));
%                     decodeas_and_dissector.(FieldsofDissector{idx}) = reshape([decodeas_and_dissector.(FieldsofDissector{idx})*2+1;decodeas_and_dissector.(FieldsofDissector{idx})*2+2],1,length(decodeas_and_dissector.(FieldsofDissector{idx}))*2);
%                 else %tmp_slash not empty
%                     decodeas_and_dissector.(FieldsofDissector{idx}) = hex2dec(tmp(1:tmp_slash-1));
%                     decodeas_and_dissector.(FieldsofDissector{idx}) = reshape([decodeas_and_dissector.(FieldsofDissector{idx})*2+1;decodeas_and_dissector.(FieldsofDissector{idx})*2+2],1,length(decodeas_and_dissector.(FieldsofDissector{idx}))*2);                    
%                     if (isempty(tmp_colon))
%                         decodeas_and_dissector.(FieldsofDissector{idx}) = {decodeas_and_dissector.(FieldsofDissector{idx}), hex2dec(tmp(tmp_slash+1:end))+1};
%                     else
%                         decodeas_and_dissector.(FieldsofDissector{idx}) = {decodeas_and_dissector.(FieldsofDissector{idx}), hex2dec(tmp(tmp_slash+1:tmp_colon-1))+1:hex2dec(tmp(tmp_colon+1:end))+1};
%                     end
%                 end
%         end
%     end

    capture(1:n) = capture_template;
    
    fid = fopen('tmp.txt');
    dstlineidx = 0;
    
    while (~feof(fid))%~isempty(line{1})
        
        linestr = textscan(fid,'%s',FILEREADBLOCKSIZE);

       
        for srclineidx = 1:5:length(linestr{1}),

            line = linestr{1}{srclineidx+1};
            dstlineidx = dstlineidx + 1;
            
            capture(dstlineidx).frametime = str2double(line(1:2))* 3600 + ...
                str2double(line(4:5))* 60 + ...
                str2double(line(7:8))* 1 + ...
                str2double(line(10:12))* 1e-3 + ...
                str2double(line(14:16))* 1e-6;
            
            % packet_bytes
            line = linestr{1}{srclineidx+4};
            packet_tokens	=	regexp(line,'([0-9a-fA-F]{2})','tokens');
            tmp				=	[packet_tokens{:}];
            
            packet_bytes_10	=	hex2dec(reshape([tmp{:}],2,length(packet_tokens))');
            packet_bytes_16	=	[tmp{:}];%reshape([tmp{:}],2,length(packet_tokens))';

%             switch dissector_base_FLAG
%                 case {10}
%                     packet_bytes	=	hex2dec(reshape([tmp{:}],2,length(packet_tokens))');
%                 case {16}
%                     packet_bytes	=	[tmp{:}];%reshape([tmp{:}],2,length(packet_tokens))';
%             end
            
            for idx=1:SizeofDissector,
                switch dissector_base_FLAG(idx)
                    case {10}
                        capture(dstlineidx).(FieldsofDissector{idx}) = dissector_weights{idx,1} * packet_bytes_10(decodeas_and_dissector.(FieldsofDissector{idx}));
                    case {16}
                        if ~iscell(decodeas_and_dissector.(FieldsofDissector{idx}))
                            packet_bytes_extracted = decodeas_and_dissector.(FieldsofDissector{idx});
                            capture(dstlineidx).(FieldsofDissector{idx}) = packet_bytes_16(packet_bytes_extracted(packet_bytes_extracted <= length(packet_bytes_16)));
                        else % iscell TRUE
                            packet_bytes_extracted = decodeas_and_dissector.(FieldsofDissector{idx});
                            capture(dstlineidx).(FieldsofDissector{idx}) = packet_bytes_16(packet_bytes_extracted{1}(packet_bytes_extracted{1} <= length(packet_bytes_16)));
                            tmp = dec2bin(hex2dec(capture(dstlineidx).(FieldsofDissector{idx})),8*length(packet_bytes_extracted{1})/2);
                            capture(dstlineidx).(FieldsofDissector{idx}) = dec2hex(bin2dec(tmp(packet_bytes_extracted{2})));
                        end
                end

%                 capture(dstlineidx).(FieldsofDissector{idx}) = dissector_weights{idx,1} * packet_bytes(decodeas_and_dissector.(FieldsofDissector{idx}));
            end
        end
    end

    
else % using WS defined disssector
    
    % reading WS dissected text file
    fid = fopen('tmp.txt');
    n = 0;
    while ~feof(fid)
        n = n + sum( fread( fid, 16384, 'char' ) == char(10) );
    end
    fclose(fid);

    
    capture_template = struct();

    for idx=1:SizeofDissector,
        p = find(FieldsofDissector{idx} == '.');
        if ~isempty(p)
            FieldsofDissector{idx} = [FieldsofDissector{idx}(1:p-1) FieldsofDissector{idx}(p+1:end)];
        end
        capture_template.(FieldsofDissector{idx}) = 0; %setfield(capture,FieldsofDissector(idx),[]);
    end
    
    capture(1:n) = capture_template;
    
    fid = fopen('tmp.txt');
    dstlineidx = 0;

    while (~feof(fid))%~isempty(line{1})
        linestr = textscan(fid,'%s',FILEREADBLOCKSIZE,'delimiter','\n');
        
        for srclineidx=1:length(linestr{1}),
            line = linestr{1}{srclineidx};
            dstlineidx = dstlineidx + 1;

            main_parser = textscan(line,'%s','delimiter',';');
            Sizeof_main_parser = size(main_parser{1},1);
            
            for idx=1:min(SizeofDissector,Sizeof_main_parser),
                switch (FieldsofDissector{idx})
                    case {'framenumber'}
                        capture(dstlineidx).framenumber = str2double(main_parser{1}{idx});
                        
                    case {'frametime'}
                        datetime_parser = textscan(main_parser{1}{idx},'%s');
                        capture(dstlineidx).frametime = str2double(datetime_parser{1}{4}(1:2))* 3600 + ...
                            str2double(datetime_parser{1}{4}(4:5))* 60 + ...
                            str2double(datetime_parser{1}{4}(7:end))* 1;
                    otherwise
                        if isempty(main_parser{1}{idx})
                            capture(dstlineidx).(FieldsofDissector{idx}) = 0;
                        elseif ~isempty(regexp(main_parser{1}{idx},'0x','ONCE'))
                            capture(dstlineidx).(FieldsofDissector{idx}) = hex2dec(main_parser{1}{idx}(3:end));
                        else
                            capture(dstlineidx).(FieldsofDissector{idx}) = str2double(main_parser{1}{idx});
                        end
                end
            end
        end
    end

end

% deleting the temporary k12text file
fclose all;
delete('tmp.txt');


