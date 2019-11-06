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

%% Parse packets:
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
      otherwise
        disp("Unhandled field: " + fld + " in packet #" + indP);
    end
  end
end
clear GVSP_FIELDS fn fld binval
%% Reorganize payloads:
pix_vec = single([packetData.payloaddata{2:339}]);
pix_vec(pix_vec > 2^14-1 | ~pix_vec) = NaN; % remove zero & >intmax(uint14)
pc = [prctile(pix_vec,0.01) prctile(pix_vec,99.99)]; % find useful percentiles
% Reshape pixel vector into a 2d image:
img = reshape(pix_vec,packetData.sizex(1),[]).';
% Plot:
figure(); 
subplot(2,1,1); imagesc(img); axis image; colorbar; caxis(500*[floor(pc(1)/500) ceil(pc(2)/500)]); colormap(gray(512));
subplot(2,1,2); histogram(pix_vec,(pc(1):pc(2)+1)-0.5); %alt: numel(unique(img));
end
