function pyshark_example()
%% Preparations
%{
1) Make sure you have wireshark installed.
2) Make sure you have python installed, and MATLAB knows where to find it 
  (can be verified using pyversion() ).
3) Go to the pyshark installation folder, e.g. "...\Anaconda3\Lib\site-packages\pyshark\",
   open config.ini and make sure it points to the tshark executable. 
   NOTE: If you do not have write access to that file, or simply do not want to 
   change it, this setting can be set during runtime.
%}
%% Load capture file
% File path:
CAPTURE_FILE = 'gigE_image.pcapng';

% Read GVSP packets from file:
cap = py.pyshark.FileCapture(CAPTURE_FILE, pyargs('custom_parameters', py.list({'-2'})) );
cap.tshark_path = 'D:\\Program Files\\Wireshark\\tshark.exe'; % OPTIONAL
cap.load_packets();

%% Pre-process packets:
% Constants:
GVSP_FIELDS = {'status', 'blockid16', 'format', 'packetid24', 'fieldid', ...
  'fieldcount', 'timestamp', 'pixel_color', 'pixel_occupy', 'pixel_id', ...
  'sizex', 'sizey', 'offsetx', 'offsety', 'paddingx', 'paddingy', 'payloaddata', ...
  'payloadtype'};

% Get all packets from the capture file:
p = py.vars(cap); p = p{'_packets'}; nP = length(p);
packetData = array2table(NaN(nP,18), 'VariableNames', GVSP_FIELDS);
packetData.payloaddata = num2cell(packetData.payloaddata);

% Go over packets and extract useful information:
for indP = 1:nP
  l = p{indP}.get_multiple_layers('GVSP');
  fn = cellfun(@string, cell(l{1}.field_names)); % get fieldnames from packet
  for indF = 1:numel(fn)
    fld = fn(indF);
    switch fld
      case {"format", "fieldid", "fieldcount"}
        packetData.(fld)(indP) = ...
          uint8(l{1}.get_field_value(fld).main_field.binary_value);   
      case {"status", "blockid16","payloadtype","paddingx","paddingy"}
        packetData.(fld)(indP) = swapbytes(typecast(...
          uint8(l{1}.get_field_value(fld).main_field.binary_value),...
          'uint16'));
      case {"payloaddata"}
        packetData.(fld)(indP) = {typecast(...
          uint8(l{1}.get_field_value(fld).main_field.binary_value),...
          'uint16')};
      case {"packetid24"}
        packetData.(fld)(indP) = swapbytes(typecast(...
          [0, uint8( l{1}.get_field_value(fld).main_field.binary_value)],...
      ...  ^ Padded with an extra byte to turn 24->32          
              'uint32'));
      case {"timestamp"}
        packetData.(fld)(indP) = swapbytes(typecast(...
          uint8( l{1}.get_field_value(fld).main_field.binary_value),...
          'uint64'));
      case {"pixel"}
        binval = uint8( l{1}.get_field_value(fld).main_field.binary_value);   
        packetData.pixel_color(indP) = binval(1);
        packetData.pixel_occupy(indP) = binval(2);
        packetData.pixel_id(indP) = swapbytes(typecast(binval(3:4),'uint16'));
      case {"sizex","sizey","offsetx","offsety"}
        packetData.(fld)(indP) = swapbytes(typecast(...
          uint8( l{1}.get_field_value(fld).main_field.binary_value),...
          'uint32'));
      case {"fieldinfo", "pixel_color", "pixel_occupy", "pixel_id"}
        % Do nothing, since already handled.
      otherwise
        disp("Unhandled field: " + fld + " in packet #" + indP);
    end
  end
end
%% Post-process packets
% Constants:
PKT_WITH_ERROR = 0; % < not defined in the GigE standard
PKT_FORMAT_LEADER = 1;
PKT_FORMAT_TRAILER = 2;
PKT_FORMAT_PAYLOAD = 3;

% Remove packets with errors and sort:
packetData = sortrows(packetData(packetData.format ~= PKT_WITH_ERROR,:),'packetid24');
  
% Discard partial GVSP images:
flag = true;
while flag
%  The reason for having a loop is that we want to update {pos_starts, pos_footrs}  
%  w/o repeating code (DRY principle). The loop will run at most twice.
   pos_starts = find(packetData.format == PKT_FORMAT_LEADER);
   pos_footrs = find(packetData.format == PKT_FORMAT_TRAILER);
   if isempty(pos_starts) || isempty(pos_footrs)
     error('No full image exists.');
   elseif numel(pos_starts) == numel(pos_footrs) && ... as many starts as ends
           all(pos_starts-pos_footrs<0) && ... end is always later than start
           size(packetData,1) == pos_footrs(end) % no extra packets
    	flag = false; %means we can stop now
   else
     packetData = packetData(pos_starts(1):pos_footrs(end),:);
   end   
end
nF = numel(pos_starts); % the supposed number of frames

%% Reorganize payloads:
for indF = 1:nF
  ps = pos_starts(indF)+1; pf = pos_footrs(indF)-1;
  assert( all(packetData.format(ps:pf) == PKT_FORMAT_PAYLOAD), ...
    'Not all packets contain payloads! Aborting...');
  pix_vec = single([packetData.payloaddata{ps:pf}]);
  pix_vec(pix_vec > 2^14-1 | ~pix_vec) = NaN; % remove zero & >intmax(uint14)
  pc = [prctile(pix_vec,0.01) prctile(pix_vec,99.99)]; % find useful percentiles
  % Reshape pixel vector into a 2d image:
  img = reshape(pix_vec,packetData.sizex(1),[]).';
  % Plot:
  figure(); 
  subplot(2,1,1); imagesc(img); axis image; colorbar; caxis(500*[floor(pc(1)/500) ceil(pc(2)/500)]); colormap(gray(512));
  subplot(2,1,2); histogram(pix_vec,(pc(1):pc(2)+1)-0.5); %alt: numel(unique(img));
end

end % pyshark_example
