function pcap2matlab_example()
isRead = true;

CAPTURE_FILE = 'gigE_image.pcapng';
%% Set up the capturing/reading parameters:
dissector = {'gvsp.status',...
             'gvsp.blockid16',...
             'gvsp.format',...
             'gvsp.packetid24',...
             'gvsp.fieldid',...
             'gvsp.fieldcount',...
             'gvsp.timestamp',...
             'gvsp.pixel.color','gvsp.pixel.occupy','gvsp.pixel.id',...
             'gvsp.sizex','gvsp.sizey',...
             'gvsp.offsetx','gvsp.offsety',...
             'gvsp.paddingx','gvsp.paddingy',...
             'gvsp.payloaddata','gvsp.payloadtype'};

capture_filter = 'udp and src port 20202';         
read_filter = 'gvsp';
%% Capture/read:   
if isRead
    % Read:
    pcap_result = pcap2matlab(read_filter,   dissector, CAPTURE_FILE);
else
    % Capture:
    pcap_result = pcap2matlab(capture_filter,dissector, 4, 700);
end
%% Verify payload:
PKT_WITH_ERROR = 0; % < not defined in the standard
PKT_FORMAT_LEADER = 1;
PKT_FORMAT_TRAILER = 2;
PKT_FORMAT_PAYLOAD = 3;
% DATA_PAYLOAD_FORMAT_H264 = 5;
% DATA_PAYLOAD_FORMAT_MULTIZONE = 6;
% DATA_ALL_IN_FORMAT = 4;
% Remove packets with errors and sort:
packet_format = vertcat(pcap_result.gvsp_format);
pcap_result = nestedSortStruct(pcap_result(packet_format ~= PKT_WITH_ERROR),...
    strrep(dissector([2,4]),'.','_'));
% Make sure we captured full images by discarding partial packets. The
% reason we have a loops is that we want to update {pos_starts, pos_footrs} w/o 
% repeating code (DRY principle);
flag = true;
while flag
   packet_format = vertcat(pcap_result.gvsp_format);
   pos_starts = find(packet_format == PKT_FORMAT_LEADER);
   pos_footrs = find(packet_format == PKT_FORMAT_TRAILER);   
   if numel(pos_starts) == numel(pos_footrs) && ...
           all(pos_starts-pos_footrs<0) && numel(pcap_result) == pos_footrs(end)
       flag = false; %means we can stop now
   else
    pcap_result = pcap_result(pos_starts(1):pos_footrs(end));
   end   
end       
% Split the pcap structure into frame-chunks:
if numel(pos_starts) < 1
    %this means we have no valid frames
    return;
elseif numel(pos_starts) == 1
    frames = {pcap_result};
else
    frames = arrayfun(@(x)pcap_result(pos_starts(x):pos_footrs(x)),...
                      1:numel(pos_starts),'un',0);
end
%% Analyze result:
for indF=1:numel(frames)
    fr = frames{indF};
    % Rebuild image from hex:
    pix_vec = single(swapbytes(typecast(uint16(...
        ... hex_img = [fr([fr.gvsp_format] == 3).gvsp_payloaddata];
               sscanf([fr([fr.gvsp_format] == 3).gvsp_payloaddata],...
               '%4x')), 'uint16')));
    % Remove invalid pixels:
    pix_vec(pix_vec > 2^14-1 | ~pix_vec) = NaN; % remove zero & >intmax(uint14)
    pc = [prctile(pix_vec,0.01) prctile(pix_vec,99.99)]; % find updated percentiles
    pix_vec(pix_vec < pc(1) | pix_vec < pc(1)) = NaN;
    % Reshape pixel vector into a 2d image:
    img = reshape(pix_vec,fr(1).gvsp_sizex,[]).';       
    % Plot:
    figure(); 
    subplot(2,1,1); imagesc(img); axis image; colorbar; caxis(500*[floor(pc(1)/500) ceil(pc(2)/500)]); colormap(gray(512));
    subplot(2,1,2); histogram(pix_vec,(pc(1):pc(2)+1)-0.5); %alt: numel(unique(img));
end